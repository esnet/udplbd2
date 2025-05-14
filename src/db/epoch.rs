// SPDX-License-Identifier: BSD-3-Clause-LBNL
// src/db/epoch.rs

use crate::db::models::Epoch;
use crate::db::{LoadBalancerDB, Result};
use crate::errors::Error;
use chrono::{DateTime, Utc};
use rand::rng;
use rand::seq::SliceRandom;
use tracing::trace;

use super::SessionState;

pub const NUM_SLOTS: usize = 512;

#[derive(Clone)]
pub struct EventSample {
    pub event_number: i64,
    pub avg_event_rate_hz: i32,
    pub local_timestamp: i64,
    pub remote_timestamp: i64,
}

pub fn predict_epoch_boundary_from_samples(
    samples: &[EventSample],
    offset: chrono::Duration,
) -> i64 {
    use chrono::Utc;

    if samples.is_empty() {
        return i64::MAX;
    }

    let latest_sample = &samples[0];

    // If we have a rate, use rate-based prediction
    if latest_sample.avg_event_rate_hz > 0 {
        let rate = latest_sample.avg_event_rate_hz as f64;
        let last_event = latest_sample.event_number;
        let last_timestamp = latest_sample.local_timestamp;

        let prediction_time = Utc::now() + offset;
        let time_diff = (prediction_time.timestamp_millis() - last_timestamp) as f64 / 1000.0;
        let additional_events = rate * time_diff;

        if additional_events > (i64::MAX - last_event) as f64 {
            return i64::MAX;
        }

        last_event + additional_events.round() as i64
    } else {
        // Use regression-based prediction
        let min_timestamp = samples
            .iter()
            .map(|s| s.local_timestamp.min(s.remote_timestamp))
            .min()
            .unwrap();

        let smallest_event = samples
            .iter()
            .filter(|s| s.event_number > 0)
            .map(|s| s.event_number)
            .min()
            .unwrap_or(0);

        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let mut sum_xx = 0.0;
        let mut sum_xy = 0.0;
        let mut count = 0;

        for sample in samples {
            if sample.event_number > 0 {
                let x = (sample.local_timestamp - min_timestamp) as f64;
                let y = (sample.event_number - smallest_event) as f64;
                sum_x += x;
                sum_y += y;
                sum_xx += x * x;
                sum_xy += x * y;
                count += 1;
            }
        }

        if count == 0 {
            return i64::MAX;
        }

        let n = count as f64;
        let denominator = n * sum_xx - sum_x * sum_x;
        if denominator == 0.0 {
            return i64::MAX;
        }

        let slope = (n * sum_xy - sum_x * sum_y) / denominator;
        let intercept = (sum_y - slope * sum_x) / n;

        let current_time = Utc::now() + offset;
        let x = (current_time.timestamp_millis() - min_timestamp) as f64;
        let predicted_y = slope * x + intercept;
        let predicted_event = smallest_event + predicted_y.round() as i64;

        if predicted_event < smallest_event {
            return i64::MAX;
        }

        predicted_event
    }
}

impl LoadBalancerDB {
    /// Predicts the next epoch boundary based on event number history,
    /// with an optional time offset adjustment to the prediction moment.
    pub async fn predict_epoch_boundary(
        &self,
        reservation_id: i64,
        offset: chrono::Duration,
    ) -> Result<i64> {
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
            AND created_at >= (unixepoch('subsec') * 1000 - 60000)
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

        let event_samples: Vec<EventSample> = samples
            .into_iter()
            .map(|s| EventSample {
                event_number: s.event_number,
                avg_event_rate_hz: s.avg_event_rate_hz as i32,
                local_timestamp: s.local_timestamp,
                remote_timestamp: s.remote_timestamp,
            })
            .collect();

        let prediction = predict_epoch_boundary_from_samples(&event_samples, offset);

        Ok(prediction)
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
                s.is_ready
            FROM session s
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
            if !state.is_ready {
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

    /// Creates a new epoch with given boundary event and slot assignments, using epoch_count from RankedEpochs CTE
    pub async fn create_epoch(
        &self,
        reservation_id: i64,
        boundary_event: i64,
        slot_assignments: &[u16],
    ) -> Result<Epoch> {
        let now = Utc::now().timestamp_millis();

        let mut tx = self.write_pool.begin().await?;

        // Get the current_epoch from the reservation
        let reservation_row = sqlx::query!(
            "SELECT current_epoch FROM reservation WHERE id = ?1",
            reservation_id
        )
        .fetch_one(&mut *tx)
        .await?;
        let new_epoch_count = reservation_row.current_epoch + 1;

        // Soft delete epochs beyond our 5 most recent
        sqlx::query!(
            r#"
            WITH RankedEpochs AS (
                SELECT id, ROW_NUMBER() OVER (ORDER BY created_at DESC) as rn
                FROM epoch
                WHERE reservation_id = ?1 AND deleted_at IS NULL
            )
            UPDATE epoch
            SET deleted_at = unixepoch('subsec') * 1000
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
                boundary_event,
                predicted_at,
                slots,
                epoch_count
            )
            VALUES (?1, ?2, ?3, ?4, ?5)
            RETURNING id, reservation_id, boundary_event, predicted_at, created_at, deleted_at, slots, epoch_count
            "#,
            reservation_id,
            boundary_event,
            now,
            slots_blob,
            new_epoch_count
        )
        .fetch_one(&mut *tx)
        .await?;

        // Update reservation's current_epoch to match
        sqlx::query!(
            "UPDATE reservation SET current_epoch = ?1 WHERE id = ?2",
            new_epoch_count,
            reservation_id
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await.map_err(Error::Database)?;

        // Build and return the Epoch struct directly
        let slots: Vec<u16> = epoch_record
            .slots
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        Ok(Epoch {
            id: epoch_record.id,
            reservation_id: epoch_record.reservation_id,
            boundary_event: epoch_record.boundary_event as u64,
            predicted_at: DateTime::<Utc>::from_timestamp_millis(epoch_record.predicted_at)
                .ok_or(Error::Parse("timestamp out of range".to_string()))?,
            created_at: DateTime::<Utc>::from_timestamp_millis(epoch_record.created_at)
                .ok_or(Error::Parse("timestamp out of range".to_string()))?,
            deleted_at: epoch_record.deleted_at.map(|dt| {
                DateTime::<Utc>::from_timestamp_millis(dt)
                    .expect("deleted_at set but out of range!")
            }),
            slots,
            epoch_count: epoch_record.epoch_count,
        })
    }

    /// Advances to the next epoch by using a provided boundary event (if any), or predicting from the DB if None.
    pub async fn advance_epoch(
        &self,
        reservation_id: i64,
        offset: chrono::Duration,
        boundary_event: Option<i64>,
    ) -> Result<Epoch> {
        let mut tx = self.write_pool.begin().await?;

        // Accumulate latest control signals into session weights
        let sessions = sqlx::query!(
            r#"
            SELECT s.id, s.weight, s.control_signal
            FROM session s
            WHERE s.reservation_id = ?1 AND s.deleted_at IS NULL
            "#,
            reservation_id
        )
        .fetch_all(&mut *tx)
        .await?;

        // Step 1: Compute new weights after applying control signals
        let mut new_weights = Vec::new();
        for session in &sessions {
            let new_weight = session.weight + session.control_signal;
            new_weights.push((session.id, new_weight));
        }

        // Step 2: Compute average of new weights
        let sum_weights: f64 = new_weights.iter().map(|(_, w)| w).sum();
        let count = new_weights.len() as f64;
        let avg_weight = if count > 0.0 {
            sum_weights / count
        } else {
            1.0
        };

        // Step 3: Compute scaling factor to make average 1000
        let scaling = 1000.0 / avg_weight;

        // Step 4: Update all session weights to scaled value
        for (id, weight) in new_weights {
            let scaled_weight = (weight * scaling).round();
            sqlx::query!(
                "UPDATE session SET weight = ?1 WHERE id = ?2",
                scaled_weight,
                id
            )
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        // Use provided boundary_event if Some, otherwise predict from DB
        let boundary_event = match boundary_event {
            Some(boundary) => boundary,
            None => match self.predict_epoch_boundary(reservation_id, offset).await {
                Ok(boundary) => boundary,
                Err(Error::NotInitialized(_)) => 0,
                Err(other_err) => return Err(other_err),
            },
        };
        let slot_assignments = self.generate_epoch_assignments(reservation_id).await?;
        if boundary_event > 0 {
            trace!("next epoch for {reservation_id} will begin at {boundary_event}");
        }

        let epoch = self
            .create_epoch(reservation_id, boundary_event, &slot_assignments)
            .await?;

        // Ensure DB is synced to disk after advancing epoch (WAL checkpoint)
        sqlx::query("PRAGMA wal_checkpoint(FULL)")
            .execute(&self.write_pool)
            .await
            .ok();

        Ok(epoch)
    }

    /// Retrieves an epoch by ID.
    pub async fn get_epoch(&self, id: i64) -> Result<Epoch> {
        let epoch_record = sqlx::query!(
            "SELECT id, reservation_id, boundary_event, predicted_at, created_at, deleted_at, slots, epoch_count
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
            boundary_event: epoch_record.boundary_event as u64,
            predicted_at: DateTime::<Utc>::from_timestamp_millis(epoch_record.predicted_at)
                .ok_or(Error::Parse("timestamp out of range".to_string()))?,
            created_at: DateTime::<Utc>::from_timestamp_millis(epoch_record.created_at)
                .ok_or(Error::Parse("timestamp out of range".to_string()))?,
            deleted_at: epoch_record.deleted_at.map(|dt| {
                DateTime::<Utc>::from_timestamp_millis(dt)
                    .expect("deleted_at set but out of range!")
            }),
            slots,
            epoch_count: epoch_record.epoch_count,
        })
    }

    pub async fn get_latest_epoch(&self, reservation_id: i64) -> Result<Epoch> {
        let epoch_record = sqlx::query!(
            r#"
            SELECT id, reservation_id, boundary_event, predicted_at, created_at, deleted_at, slots, epoch_count
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
            boundary_event: epoch_record.boundary_event as u64,
            predicted_at: DateTime::<Utc>::from_timestamp_millis(epoch_record.predicted_at)
                .ok_or(Error::Parse("timestamp out of range".to_string()))?,
            created_at: DateTime::<Utc>::from_timestamp_millis(epoch_record.created_at)
                .ok_or(Error::Parse("created_at out of range".to_string()))?,
            deleted_at: epoch_record.deleted_at.map(|dt| {
                DateTime::<Utc>::from_timestamp_millis(dt)
                    .expect("deleted_at set but out of range!")
            }),
            slots,
            epoch_count: epoch_record.epoch_count,
        })
    }

    /// Gets the latest session states for a reservation
    pub async fn get_latest_session_states(
        &self,
        reservation_id: i64,
    ) -> Result<Vec<(u16, SessionState)>> {
        let session_states = sqlx::query!(
            r#"
            SELECT
                s.id as session_id,
                ss.timestamp as "timestamp?",
                ss.is_ready as "is_ready?",
                ss.fill_percent as "fill_percent?",
                ss.control_signal as "control_signal?",
                ss.total_events_recv as "total_events_recv?",
                ss.total_events_reassembled as "total_events_reassembled?",
                ss.total_events_reassembly_err as "total_events_reassembly_err?",
                ss.total_events_dequeued as "total_events_dequeued?",
                ss.total_event_enqueue_err as "total_event_enqueue_err?",
                ss.total_bytes_recv as "total_bytes_recv?",
                ss.total_packets_recv as "total_packets_recv?"
            FROM session s
            LEFT JOIN session_state ss ON s.latest_session_state_id = ss.id
            WHERE s.reservation_id = ?1
            AND s.deleted_at IS NULL
            "#,
            reservation_id
        )
        .fetch_all(&self.read_pool)
        .await?;

        let mut result = Vec::new();
        for state in session_states {
            let member_id = (state.session_id % (u16::MAX as i64)) as u16;

            // Only include sessions that have state data
            if let (Some(timestamp), Some(is_ready), Some(fill_percent)) =
                (state.timestamp, state.is_ready, state.fill_percent)
            {
                let session_state = SessionState {
                    timestamp: DateTime::<Utc>::from_timestamp_millis(timestamp)
                        .ok_or(Error::Parse("timestamp out of range".to_string()))?,
                    is_ready,
                    fill_percent,
                    control_signal: state.control_signal.unwrap_or(0.0),
                    total_events_recv: state.total_events_recv.unwrap_or(0) as u64,
                    total_events_reassembled: state.total_events_reassembled.unwrap_or(0) as u64,
                    total_events_reassembly_err: state.total_events_reassembly_err.unwrap_or(0)
                        as u64,
                    total_events_dequeued: state.total_events_dequeued.unwrap_or(0) as u64,
                    total_event_enqueue_err: state.total_event_enqueue_err.unwrap_or(0) as u64,
                    total_bytes_recv: state.total_bytes_recv.unwrap_or(0) as u64,
                    total_packets_recv: state.total_packets_recv.unwrap_or(0) as u64,
                };

                result.push((member_id, session_state));
            }
        }

        Ok(result)
    }
}
