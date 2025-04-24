// src/db/reservation.rs

use crate::db::models::Reservation;
use crate::db::{LoadBalancerDB, Result};
use crate::errors::Error;
use chrono::{DateTime, Duration, Utc};
use std::net::IpAddr;

impl LoadBalancerDB {
    /// Creates a new reservation.
    pub async fn create_reservation(&self, lb_id: i64, duration: Duration) -> Result<Reservation> {
        let reserved_until = (Utc::now() + duration).timestamp_millis();

        // Find the first available fpga_lb_id
        let mut fpga_lb_id: i64 = 0;
        let active_reservations =
            sqlx::query!("SELECT fpga_lb_id FROM reservation WHERE deleted_at IS NULL")
                .fetch_all(&self.read_pool)
                .await?;

        let mut used_ids = std::collections::HashSet::new();
        for res in active_reservations {
            used_ids.insert(res.fpga_lb_id);
        }

        while used_ids.contains(&fpga_lb_id) {
            fpga_lb_id += 1;
            if fpga_lb_id >= 8 {
                return Err(Error::ResourceExhausted(
                    "Max number of reservations reached".to_string(),
                ));
            }
        }

        let record = sqlx::query!(
            "INSERT INTO reservation (loadbalancer_id, reserved_until, fpga_lb_id)
             VALUES (?1, ?2, ?3)
             RETURNING id, loadbalancer_id, reserved_until, created_at, deleted_at, fpga_lb_id",
            lb_id,
            reserved_until,
            fpga_lb_id
        )
        .fetch_one(&self.write_pool)
        .await?;

        Ok(Reservation {
            id: record.id,
            loadbalancer_id: record.loadbalancer_id,
            reserved_until: DateTime::<Utc>::from_timestamp_millis(record.reserved_until)
                .ok_or(Error::Parse("reserved_until out of range".to_string()))?,
            created_at: DateTime::<Utc>::from_timestamp_millis(record.created_at)
                .ok_or(Error::Parse("created_at out of range".to_string()))?,
            deleted_at: record.deleted_at.map(|dt| {
                DateTime::<Utc>::from_timestamp_millis(dt)
                    .expect("deleted_at set but out of range!")
            }),
            fpga_lb_id: record.fpga_lb_id as u16,
        })
    }

    /// Retrieves a reservation by ID.
    pub async fn get_reservation(&self, id: i64) -> Result<Reservation> {
        let reservation_record = sqlx::query!(
            "SELECT id, loadbalancer_id, reserved_until, created_at, deleted_at, fpga_lb_id
             FROM reservation
             WHERE id = ?1 AND deleted_at IS NULL",
            id
        )
        .fetch_optional(&self.read_pool)
        .await?
        .ok_or_else(|| Error::NotFound(format!("Reservation {id} not found")))?;

        Ok(Reservation {
            id: reservation_record.id,
            loadbalancer_id: reservation_record.loadbalancer_id,
            reserved_until: DateTime::<Utc>::from_timestamp_millis(
                reservation_record.reserved_until,
            )
            .ok_or(Error::Parse("reserved_until out of range".to_string()))?,
            created_at: DateTime::<Utc>::from_timestamp_millis(reservation_record.created_at)
                .ok_or(Error::Parse("created_at out of range".to_string()))?,
            deleted_at: reservation_record.deleted_at.map(|dt| {
                DateTime::<Utc>::from_timestamp_millis(dt)
                    .expect("deleted_at set but out of range!")
            }),
            fpga_lb_id: reservation_record.fpga_lb_id as u16,
        })
    }

    /// Gets all sessions for a reservation
    pub async fn get_reservation_sessions(
        &self,
        reservation_id: i64,
    ) -> Result<Vec<crate::db::models::Session>> {
        let sessions = sqlx::query!(
            r#"
            SELECT
                id, reservation_id, name, weight, ip_address, udp_port, port_range,
                mac_address, min_factor, max_factor, keep_lb_header, created_at, deleted_at
            FROM session
            WHERE reservation_id = ?1 AND deleted_at IS NULL
            "#,
            reservation_id
        )
        .fetch_all(&self.read_pool)
        .await?
        .into_iter()
        .filter_map(|record| {
            Some(crate::db::models::Session {
                id: record.id,
                reservation_id: record.reservation_id,
                name: record.name,
                weight: record.weight,
                ip_address: record.ip_address.parse().ok()?,
                udp_port: record.udp_port as u16,
                port_range: record.port_range as u16,
                mac_address: record.mac_address,
                min_factor: record.min_factor,
                max_factor: record.max_factor,
                keep_lb_header: record.keep_lb_header == 1,
                created_at: DateTime::<Utc>::from_timestamp_millis(record.created_at)
                    .expect("created_at out of range"),
                deleted_at: None,
            })
        })
        .collect();

        Ok(sessions)
    }

    /// Gets all senders for a reservation
    pub async fn get_reservation_senders(&self, reservation_id: i64) -> Result<Vec<IpAddr>> {
        let senders = sqlx::query!(
            "SELECT ip_address FROM sender
             WHERE reservation_id = ?1 AND deleted_at IS NULL",
            reservation_id
        )
        .fetch_all(&self.read_pool)
        .await?
        .into_iter()
        .filter_map(|record| record.ip_address?.parse::<IpAddr>().ok())
        .collect();

        Ok(senders)
    }

    /// Adds a sender to a reservation.
    pub async fn add_sender(&self, reservation_id: i64, addr: IpAddr) -> Result<()> {
        let addr_str = addr.to_string();

        // Check if the sender already exists but was soft-deleted
        let existing_sender = sqlx::query!(
            "SELECT id FROM sender WHERE reservation_id = ?1 AND ip_address = ?2",
            reservation_id,
            addr_str
        )
        .fetch_optional(&self.write_pool)
        .await?;

        if let Some(record) = existing_sender {
            // If the sender exists, update the deleted_at field to NULL
            sqlx::query!(
                "UPDATE sender SET deleted_at = NULL WHERE id = ?1",
                record.id
            )
            .execute(&self.write_pool)
            .await
            .map_err(Error::Database)?;
        } else {
            // Otherwise, insert a new sender record
            sqlx::query!(
                "INSERT INTO sender (reservation_id, ip_address) VALUES (?1, ?2)",
                reservation_id,
                addr_str
            )
            .execute(&self.write_pool)
            .await
            .map_err(Error::Database)?;
        }

        Ok(())
    }

    /// Removes a sender from a reservation by soft deleting.
    pub async fn remove_sender(&self, reservation_id: i64, addr: IpAddr) -> Result<()> {
        let addr_str = addr.to_string();
        sqlx::query!(
            "UPDATE sender SET deleted_at = unixepoch('subsec') * 1000
             WHERE reservation_id = ?1 AND ip_address = ?2",
            reservation_id,
            addr_str
        )
        .execute(&self.write_pool)
        .await
        .map_err(Error::Database)?;
        Ok(())
    }

    pub async fn create_event_number(
        &self,
        reservation_id: i64,
        event_number: i64,
        avg_event_rate_hz: i32,
        local_timestamp: chrono::DateTime<chrono::Utc>,
        remote_timestamp: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        let local_timestamp_ms = local_timestamp.timestamp_millis();
        let remote_timestamp_ms = remote_timestamp.timestamp_millis();
        sqlx::query!(
            "INSERT INTO event_number (
                reservation_id, event_number, avg_event_rate_hz,
                local_timestamp, remote_timestamp
            ) VALUES (?1, ?2, ?3, ?4, ?5)",
            reservation_id,
            event_number,
            avg_event_rate_hz,
            local_timestamp_ms,
            remote_timestamp_ms
        )
        .execute(&self.write_pool)
        .await
        .map_err(Error::Database)?;

        Ok(())
    }

    pub async fn list_reservations(&self) -> Result<Vec<Reservation>> {
        let records = sqlx::query!(
            "SELECT id, loadbalancer_id, reserved_until, created_at, deleted_at, fpga_lb_id
             FROM reservation
             WHERE deleted_at IS NULL"
        )
        .fetch_all(&self.read_pool)
        .await?;

        let mut reservations = Vec::with_capacity(records.len());
        for record in records {
            reservations.push(Reservation {
                id: record.id,
                loadbalancer_id: record.loadbalancer_id,
                reserved_until: DateTime::<Utc>::from_timestamp_millis(record.reserved_until)
                    .ok_or(Error::Parse("reserved_until out of range".to_string()))?,
                created_at: DateTime::<Utc>::from_timestamp_millis(record.created_at)
                    .ok_or(Error::Parse("created_at out of range".to_string()))?,
                deleted_at: record.deleted_at.map(|dt| {
                    DateTime::<Utc>::from_timestamp_millis(dt)
                        .expect("deleted_at set but out of range!")
                }),
                fpga_lb_id: record.fpga_lb_id as u16,
            });
        }

        Ok(reservations)
    }

    pub async fn list_reservations_with_load_balancer(
        &self,
    ) -> Result<Vec<(Reservation, crate::db::models::LoadBalancer)>> {
        let records = sqlx::query!(
            r#"
            SELECT r.id res_id, r.loadbalancer_id, r.reserved_until, r.created_at res_created_at, r.fpga_lb_id,
                   lb.id lb_id, lb.name, lb.unicast_mac_address, lb.broadcast_mac_address,
                   lb.unicast_ipv4_address, lb.unicast_ipv6_address, lb.event_number_udp_port,
                   lb.created_at lb_created_at
            FROM reservation r
            JOIN loadbalancer lb ON r.loadbalancer_id = lb.id
            WHERE r.deleted_at IS NULL AND lb.deleted_at IS NULL
            "#,
        )
        .fetch_all(&self.read_pool)
        .await?;

        let mut reservations = Vec::with_capacity(records.len());
        for record in records {
            reservations.push((
                Reservation {
                    id: record.res_id,
                    loadbalancer_id: record.loadbalancer_id,
                    reserved_until: DateTime::<Utc>::from_timestamp_millis(record.reserved_until)
                        .ok_or(Error::Parse(
                        "reserved_until out of range".to_string(),
                    ))?,
                    created_at: DateTime::<Utc>::from_timestamp_millis(record.res_created_at)
                        .ok_or(Error::Parse("created_at out of range".to_string()))?,
                    deleted_at: None,
                    fpga_lb_id: record.fpga_lb_id as u16,
                },
                crate::db::models::LoadBalancer {
                    id: record.lb_id,
                    name: record.name,
                    unicast_mac_address: record
                        .unicast_mac_address
                        .parse()
                        .map_err(|_| Error::Config("Invalid unicast MAC address".into()))?,
                    broadcast_mac_address: record
                        .broadcast_mac_address
                        .parse()
                        .map_err(|_| Error::Config("Invalid broadcast MAC address".into()))?,
                    unicast_ipv4_address: record
                        .unicast_ipv4_address
                        .parse()
                        .map_err(|_| Error::Config("Invalid IPv4 address".into()))?,
                    unicast_ipv6_address: record
                        .unicast_ipv6_address
                        .parse()
                        .map_err(|_| Error::Config("Invalid IPv6 address".into()))?,
                    event_number_udp_port: record.event_number_udp_port as u16,
                    created_at: DateTime::<Utc>::from_timestamp_millis(record.lb_created_at)
                        .ok_or(Error::Parse("created_at out of range".to_string()))?,
                    deleted_at: None,
                },
            ));
        }

        Ok(reservations)
    }

    pub async fn delete_reservation(&self, reservation_id: i64) -> Result<()> {
        let mut tx = self.write_pool.begin().await?;

        // Hard delete token permissions for all sessions in this reservation
        sqlx::query!(
            "DELETE FROM token_session_permission
             WHERE session_id IN (
                 SELECT id FROM session WHERE reservation_id = ?1
             )",
            reservation_id
        )
        .execute(&mut *tx)
        .await
        .map_err(Error::Database)?;

        // Hard delete token permissions for the reservation
        sqlx::query!(
            "DELETE FROM token_reservation_permission WHERE reservation_id = ?1",
            reservation_id
        )
        .execute(&mut *tx)
        .await
        .map_err(Error::Database)?;

        // Soft delete associated sessions
        sqlx::query!(
            "UPDATE session SET deleted_at = unixepoch('subsec') * 1000 WHERE reservation_id = ?1",
            reservation_id
        )
        .execute(&mut *tx)
        .await
        .map_err(Error::Database)?;

        // Soft delete the reservation
        sqlx::query!(
            "UPDATE reservation SET deleted_at = unixepoch('subsec') * 1000 WHERE id = ?1",
            reservation_id
        )
        .execute(&mut *tx)
        .await
        .map_err(Error::Database)?;

        tx.commit().await.map_err(Error::Database)?;

        // Delete tokens with no remaining permissions
        self.delete_tokens_with_no_permissions().await?;

        Ok(())
    }
}
