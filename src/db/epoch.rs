// src/db/epoch.rs

use crate::db::models::Epoch;
use crate::db::{LoadBalancerDB, Result};
use crate::errors::Error;
use chrono::{DateTime, Utc};
use rand::rng;
use rand::seq::SliceRandom;
use tracing::trace;
use uuid::Uuid;

pub const NUM_SLOTS: usize = 512;

impl LoadBalancerDB {
    /// Predicts the next epoch boundary based on event number history
    pub async fn predict_epoch_boundary(&self, reservation_id: i64) -> Result<i64> {
        // Get the most recent event number samples
        let samples = sqlx::query!(
            r#"
            SELECT
                event_number,
                avg_event_rate_hz,
                local_timestamp,
                remote_timestamp
            FROM event_number
            WHERE reservation_id = ?1
            ORDER BY created_at DESC
            LIMIT 10
            "#,
            reservation_id
        )
        .fetch_all(&self.read_pool)
        .await?;

        if samples.is_empty() {
            return Err(Error::NotInitialized("event data needed".into()));
        }

        let latest_sample = &samples[0];

        // If we have a rate, use rate-based prediction
        if latest_sample.avg_event_rate_hz > 0 {
            let rate = latest_sample.avg_event_rate_hz as f64;
            let last_event = latest_sample.event_number;
            let last_timestamp = latest_sample.local_timestamp.and_utc();
            let prediction_time: DateTime<Utc> = Utc::now();

            if prediction_time < last_timestamp {
                return Ok(last_event);
            }

            let time_diff = (prediction_time - last_timestamp).num_seconds() as f64;
            let additional_events = rate * time_diff;

            // Check for overflow
            if additional_events > (i64::MAX - last_event) as f64 {
                return Ok(i64::MAX);
            }

            Ok(last_event + additional_events.round() as i64)
        } else {
            // Use regression-based prediction
            let min_timestamp = samples
                .iter()
                .map(|s| s.local_timestamp.min(s.remote_timestamp))
                .min()
                .unwrap()
                .and_utc();

            let smallest_event = samples
                .iter()
                .filter(|s| s.event_number > 0)
                .map(|s| s.event_number)
                .min()
                .unwrap_or(0);

            // Calculate regression parameters
            let mut sum_x = 0.0;
            let mut sum_y = 0.0;
            let mut sum_xx = 0.0;
            let mut sum_xy = 0.0;
            let mut count = 0;

            for sample in &samples {
                if sample.event_number > 0 {
                    let x = (sample.local_timestamp.and_utc() - min_timestamp)
                        .num_microseconds()
                        .unwrap() as f64;
                    let y = (sample.event_number - smallest_event) as f64;
                    sum_x += x;
                    sum_y += y;
                    sum_xx += x * x;
                    sum_xy += x * y;
                    count += 1;
                }
            }

            if count == 0 {
                return Ok(i64::MAX);
            }

            let n = f64::from(count);
            let denominator = n * sum_xx - sum_x * sum_x;
            if denominator == 0.0 {
                return Ok(i64::MAX);
            }

            let slope = (n * sum_xy - sum_x * sum_y) / denominator;
            let intercept = (sum_y - slope * sum_x) / n;

            // Predict using regression
            let current_time = Utc::now();
            let x = (current_time - min_timestamp).num_microseconds().unwrap() as f64;
            let predicted_y = slope * x + intercept;
            let predicted_event = smallest_event + predicted_y.round() as i64;

            // Check for overflow
            if predicted_event < smallest_event {
                return Ok(i64::MAX);
            }

            Ok(predicted_event)
        }
    }

    /// Generates slot assignments based on current session states
    pub async fn generate_epoch_assignments(&self, reservation_id: i64) -> Result<Vec<u16>> {
        // Get the latest session state for each session with readiness info
        let session_states = sqlx::query!(
            r#"
            SELECT
                s.id as session_id,
                s.weight as relative_priority,
                s.min_factor,
                s.max_factor,
                COALESCE(latest_state.is_ready, true) as is_ready
            FROM session s
            LEFT JOIN (
                SELECT
                    session_id,
                    is_ready
                FROM session_state
                GROUP BY session_id
                HAVING created_at = MAX(created_at)
            ) latest_state ON s.id = latest_state.session_id
            WHERE s.reservation_id = $1
            AND s.deleted_at IS NULL
            "#,
            reservation_id
        )
        .fetch_all(&self.read_pool)
        .await?;

        let mut slots = vec![65535u16; NUM_SLOTS];

        // Early return if no sessions
        if session_states.is_empty() {
            return Ok(slots);
        }

        // Collect member information
        let mut member_ids = Vec::new();
        let mut relative_priorities = Vec::new();
        let mut member_constraints = std::collections::HashMap::new();
        let mut total_relative_priority = 0.0;

        for state in &session_states {
            if state.is_ready == 0 {
                continue;
            }

            let member_id = (state.session_id % (u16::MAX as i64)) as u16;
            member_ids.push(member_id);
            relative_priorities.push(state.relative_priority as f32);
            total_relative_priority += state.relative_priority as f32;
            member_constraints.insert(
                member_id,
                [state.min_factor as f32, state.max_factor as f32],
            );
        }

        let member_count = member_ids.len();
        if member_count == 0 {
            return Ok(slots);
        }

        let even_slot_distribution = NUM_SLOTS / member_count;

        // Step 1: Calculate base slots and apply constraints
        let mut assigned_slots = std::collections::HashMap::new();
        let mut total_assigned_slots = 0;

        for i in 0..member_count {
            let member_id = member_ids[i];
            let normalized_priority = relative_priorities[i] / total_relative_priority;
            let base_slots = (NUM_SLOTS as f64 * f64::from(normalized_priority)).round() as i32;

            let constraints = member_constraints[&member_id];
            let min_slots = (even_slot_distribution as f32 * constraints[0]).round() as i32;
            let max_slots = if constraints[1] == 0.0 {
                NUM_SLOTS as i32
            } else {
                (even_slot_distribution as f32 * constraints[1]).round() as i32
            };

            let mut slots_to_add = base_slots;
            if slots_to_add < min_slots {
                slots_to_add = min_slots;
            }
            if slots_to_add > max_slots {
                slots_to_add = max_slots;
            }

            assigned_slots.insert(member_id, slots_to_add);
            total_assigned_slots += slots_to_add;
        }

        // Step 2: Distribute leftover slots evenly
        let mut leftover_slots = NUM_SLOTS as i32 - total_assigned_slots;
        while leftover_slots > 0 {
            let index = (leftover_slots as usize) % member_count;
            let member_id = member_ids[index];
            *assigned_slots.get_mut(&member_id).unwrap() += 1;
            leftover_slots -= 1;
        }

        // Step 3: Assign slots in round-robin fashion
        let mut i = 0;
        'outer: loop {
            for &member_id in &member_ids {
                if let Some(remaining) = assigned_slots.get_mut(&member_id) {
                    if *remaining > 0 {
                        slots[i] = member_id;
                        *remaining -= 1;
                        i += 1;
                        if i >= NUM_SLOTS {
                            break 'outer;
                        }
                    }
                }
            }
            if i >= NUM_SLOTS {
                break;
            }
        }

        // Step 4: Shuffle slots
        let mut rng = rng();
        slots.shuffle(&mut rng);

        Ok(slots)
    }

    /// Creates a new epoch with given boundary event and slot assignments
    pub async fn create_epoch(
        &self,
        reservation_id: i64,
        boundary_event: i64,
        slot_assignments: &[u16],
    ) -> Result<Epoch> {
        let epoch_fpga_id = Uuid::new_v4().to_string();
        let now = Utc::now().naive_utc();

        let mut tx = self.write_pool.begin().await?;

        // Soft delete epochs beyond our 5 most recent
        sqlx::query!(
            r#"
            WITH RankedEpochs AS (
                SELECT id, ROW_NUMBER() OVER (ORDER BY created_at DESC) as rn
                FROM epoch
                WHERE reservation_id = ?1 AND deleted_at IS NULL
            )
            UPDATE epoch
            SET deleted_at = CURRENT_TIMESTAMP
            WHERE id IN (
                SELECT id FROM RankedEpochs WHERE rn > 4
            )
            "#,
            reservation_id
        )
        .execute(&mut *tx)
        .await?;

        let slots_blob: Vec<u8> = slot_assignments
            .iter()
            .flat_map(|&x| x.to_le_bytes())
            .collect();

        let epoch_record = sqlx::query!(
            r#"
            INSERT INTO epoch (
                reservation_id,
                epoch_fpga_id,
                boundary_event,
                predicted_at,
                slots
            )
            VALUES (?1, ?2, ?3, ?4, ?5)
            RETURNING id
            "#,
            reservation_id,
            epoch_fpga_id,
            boundary_event,
            now,
            slots_blob
        )
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await.map_err(Error::Database)?;

        self.get_epoch(epoch_record.id).await
    }

    /// Advances to the next epoch by predicting boundary and generating assignments
    pub async fn advance_epoch(&self, reservation_id: i64) -> Result<Epoch> {
        let boundary_event = match self.predict_epoch_boundary(reservation_id).await {
            Ok(boundary) => boundary,
            Err(Error::NotInitialized(_)) => 0,
            Err(other_err) => return Err(other_err),
        };
        let slot_assignments = self.generate_epoch_assignments(reservation_id).await?;
        if boundary_event > 0 {
            trace!("next epoch for {reservation_id} will begin at {boundary_event}");
        }
        self.create_epoch(reservation_id, boundary_event, &slot_assignments)
            .await
    }

    /// Retrieves an epoch by ID.
    pub async fn get_epoch(&self, id: i64) -> Result<Epoch> {
        let epoch_record = sqlx::query!(
            "SELECT id, reservation_id, epoch_fpga_id, boundary_event, predicted_at, created_at, deleted_at, slots
             FROM epoch
             WHERE id = ?1 AND deleted_at IS NULL",
            id
        )
        .fetch_optional(&self.read_pool)
        .await?;

        let epoch_record =
            epoch_record.ok_or_else(|| Error::NotFound(format!("Epoch {id} not found")))?;

        let slots: Vec<u16> = epoch_record
            .slots
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        Ok(Epoch {
            id: epoch_record.id,
            reservation_id: epoch_record.reservation_id,
            epoch_fpga_id: epoch_record.epoch_fpga_id,
            boundary_event: epoch_record.boundary_event as u64,
            predicted_at: epoch_record.predicted_at.and_utc(),
            created_at: epoch_record.created_at.and_utc(),
            deleted_at: epoch_record.deleted_at.map(|dt| dt.and_utc()),
            slots,
        })
    }

    pub async fn get_latest_epoch(&self, reservation_id: i64) -> Result<Epoch> {
        let epoch_record = sqlx::query!(
            r#"
            SELECT id, reservation_id, epoch_fpga_id, boundary_event, predicted_at, created_at, deleted_at, slots
            FROM epoch
            WHERE reservation_id = ?1 AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            reservation_id
        )
        .fetch_optional(&self.read_pool)
        .await?;

        let epoch_record = epoch_record.ok_or_else(|| {
            Error::NotFound(format!("No epochs found for reservation {reservation_id}"))
        })?;

        let slots: Vec<u16> = epoch_record
            .slots
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        Ok(Epoch {
            id: epoch_record.id,
            reservation_id: epoch_record.reservation_id,
            epoch_fpga_id: epoch_record.epoch_fpga_id,
            boundary_event: epoch_record.boundary_event as u64,
            predicted_at: epoch_record.predicted_at.and_utc(),
            created_at: epoch_record.created_at.and_utc(),
            deleted_at: epoch_record.deleted_at.map(|dt| dt.and_utc()),
            slots,
        })
    }
}
