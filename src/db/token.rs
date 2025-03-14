// src/db/token.rs

use crate::db::models::{Permission, PermissionType, Resource};
use crate::db::{LoadBalancerDB, Result};
use crate::errors::Error;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::Sqlite;
use uuid::Uuid;

#[derive(Debug)]
pub struct TokenDetails {
    pub id: i64,
    pub name: String,
    pub permissions: Vec<Permission>,
    pub created_at: DateTime<Utc>,
}

impl LoadBalancerDB {
    pub async fn create_token(
        &self,
        name: &str,
        parent_token: Option<&str>,
        permissions: Vec<Permission>,
    ) -> Result<String> {
        use sqlx::Transaction;

        let token = Uuid::new_v4().to_string().replace("-", "");
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        let mut tx: Transaction<'_, Sqlite> = self.write_pool.begin().await?;

        // Get parent token ID if provided
        let parent_token_id = if let Some(parent) = parent_token {
            let mut hasher = Sha256::new();
            hasher.update(parent.as_bytes());
            let parent_hash = hex::encode(hasher.finalize());

            let parent_id = sqlx::query!("SELECT id FROM token WHERE token_hash = ?1", parent_hash)
                .fetch_optional(&mut *tx)
                .await?
                .map(|r| r.id);

            if parent_id.is_none() {
                return Err(Error::NotFound("parent token not found".to_string()));
            }

            parent_id
        } else {
            None
        };

        let token_id: i64 = sqlx::query!(
            "INSERT INTO token (token_hash, name, parent_token_id) VALUES (?1, ?2, ?3) RETURNING id",
            token_hash,
            name,
            parent_token_id
        )
        .fetch_one(&mut *tx)
        .await?
        .id;

        for perm in permissions {
            let permission_str = perm.permission.to_string();
            match perm.resource {
                Resource::All => {
                    sqlx::query!(
                        "INSERT INTO token_global_permission (token_id, permission)
                         VALUES (?1, ?2)",
                        token_id,
                        permission_str
                    )
                    .execute(&mut *tx)
                    .await?;
                }
                Resource::LoadBalancer(lb_id) => {
                    sqlx::query!(
                        "INSERT INTO token_loadbalancer_permission (token_id, loadbalancer_id, permission)
                         VALUES (?1, ?2, ?3)",
                        token_id,
                        lb_id,
                        permission_str
                    )
                    .execute(&mut *tx)
                    .await?;
                }
                Resource::Reservation(res_id) => {
                    sqlx::query!(
                        "INSERT INTO token_reservation_permission (token_id, reservation_id, permission)
                         VALUES (?1, ?2, ?3)",
                        token_id,
                        res_id,
                        permission_str
                    )
                    .execute(&mut *tx)
                    .await?;
                }
                Resource::Session(session_id) => {
                    sqlx::query!(
                        "INSERT INTO token_session_permission (token_id, session_id, permission)
                         VALUES (?1, ?2, ?3)",
                        token_id,
                        session_id,
                        permission_str
                    )
                    .execute(&mut *tx)
                    .await?;
                }
            }
        }

        tx.commit().await.map_err(Error::Database)?;
        Ok(token)
    }

    // Helper function to check if one permission implies another
    pub fn permission_implies(granted: &PermissionType, required: &PermissionType) -> bool {
        use PermissionType::*;
        match (granted, required) {
            // Update can do everything
            (Update, _) => true,
            // Reserve can reserve and read
            (Reserve, Reserve) | (Reserve, ReadOnly) => true,
            // Register can register and read
            (Register, Register) | (Register, ReadOnly) => true,
            // ReadOnly can only read
            (ReadOnly, ReadOnly) => true,
            // All other combinations are false
            _ => false,
        }
    }

    pub async fn get_token_id(&self, token: &str) -> Result<Option<i64>> {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        let token_id = sqlx::query!("SELECT id FROM token WHERE token_hash = ?1", token_hash)
            .fetch_optional(&self.read_pool)
            .await?
            .map(|record| record.id);

        Ok(token_id)
    }

    pub async fn get_token_details(&self, token: &str) -> Result<Option<TokenDetails>> {
        match self.get_token_id(token).await {
            Ok(Some(id)) => self.get_token_details_by_id(id).await,
            Ok(None) => Err(Error::NotFound("token not found".to_string())),
            Err(e) => Err(e),
        }
    }

    pub async fn get_token_details_by_id(&self, id: i64) -> Result<Option<TokenDetails>> {
        let token_record = sqlx::query!("SELECT id, name, created_at FROM token WHERE id = ?1", id)
            .fetch_optional(&self.read_pool)
            .await?;

        let token_record = match token_record {
            Some(record) => record,
            None => return Ok(None),
        };

        let mut permissions = Vec::new();

        // Get global permissions
        let global_perms = sqlx::query!(
            "SELECT permission FROM token_global_permission WHERE token_id = ?1",
            id
        )
        .fetch_all(&self.read_pool)
        .await?;

        for perm in global_perms {
            permissions.push(Permission {
                resource: Resource::All,
                permission: perm.permission.parse().unwrap(),
            });
        }

        // Get loadbalancer permissions
        let lb_perms = sqlx::query!(
            "SELECT loadbalancer_id, permission FROM token_loadbalancer_permission WHERE token_id = ?1",
            id
        )
        .fetch_all(&self.read_pool)
        .await?;

        for perm in lb_perms {
            permissions.push(Permission {
                resource: Resource::LoadBalancer(perm.loadbalancer_id),
                permission: perm.permission.parse().unwrap(),
            });
        }

        // Get reservation permissions
        let res_perms = sqlx::query!(
            "SELECT reservation_id, permission FROM token_reservation_permission WHERE token_id = ?1",
            id
        )
        .fetch_all(&self.read_pool)
        .await?;

        for perm in res_perms {
            permissions.push(Permission {
                resource: Resource::Reservation(perm.reservation_id),
                permission: perm.permission.parse().unwrap(),
            });
        }

        // Get session permissions
        let session_perms = sqlx::query!(
            "SELECT session_id, permission FROM token_session_permission WHERE token_id = ?1",
            id
        )
        .fetch_all(&self.read_pool)
        .await?;

        for perm in session_perms {
            permissions.push(Permission {
                resource: Resource::Session(perm.session_id),
                permission: perm.permission.parse().unwrap(),
            });
        }

        Ok(Some(TokenDetails {
            id: token_record.id,
            name: token_record.name,
            permissions,
            created_at: DateTime::<Utc>::from_naive_utc_and_offset(token_record.created_at, Utc),
        }))
    }

    pub async fn list_child_tokens(&self, parent_token: &str) -> Result<Vec<TokenDetails>> {
        let parent_id = match self.get_token_id(parent_token).await? {
            Some(id) => id,
            None => return Ok(Vec::new()),
        };

        self.list_child_tokens_by_id(parent_id).await
    }

    pub async fn list_child_tokens_by_id(&self, parent_id: i64) -> Result<Vec<TokenDetails>> {
        let child_tokens =
            sqlx::query!("SELECT id FROM token WHERE parent_token_id = ?1", parent_id)
                .fetch_all(&self.read_pool)
                .await?;

        let mut children = Vec::new();
        for child in child_tokens {
            if let Some(details) = self.get_token_details_by_id(child.id).await? {
                children.push(details);
            }
        }

        Ok(children)
    }

    pub async fn validate_token(
        &self,
        token: &str,
        resource: Resource,
        required_permission: PermissionType,
    ) -> Result<bool> {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        let token_id = match sqlx::query!("SELECT id FROM token WHERE token_hash = ?1", token_hash)
            .fetch_optional(&self.read_pool)
            .await?
        {
            Some(record) => record.id,
            None => return Ok(false),
        };

        // Check global permissions first
        let global_perms = sqlx::query!(
            "SELECT permission FROM token_global_permission WHERE token_id = ?1",
            token_id
        )
        .fetch_all(&self.read_pool)
        .await?;

        for perm in global_perms {
            let permission: PermissionType = perm.permission.parse().unwrap();
            if Self::permission_implies(&permission, &required_permission) {
                return Ok(true);
            }
        }

        // Check specific resource permissions based on resource type
        match resource {
            Resource::All => {
                // Only global permissions can grant access to all resources
                Ok(false)
            }
            Resource::LoadBalancer(lb_id) => {
                let perms = sqlx::query!(
                    "SELECT permission
                     FROM token_loadbalancer_permission
                     WHERE token_id = ?1 AND loadbalancer_id = ?2",
                    token_id,
                    lb_id
                )
                .fetch_all(&self.read_pool)
                .await?;

                for perm in perms {
                    let permission: PermissionType = perm.permission.parse().unwrap();
                    if Self::permission_implies(&permission, &required_permission) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Resource::Reservation(res_id) => {
                // Check direct reservation permissions
                let res_perms = sqlx::query!(
                    "SELECT permission
                     FROM token_reservation_permission
                     WHERE token_id = ?1 AND reservation_id = ?2",
                    token_id,
                    res_id
                )
                .fetch_all(&self.read_pool)
                .await?;

                for perm in res_perms {
                    let permission: PermissionType = perm.permission.parse().unwrap();
                    if Self::permission_implies(&permission, &required_permission) {
                        return Ok(true);
                    }
                }

                // Check if there's a loadbalancer permission that covers this reservation
                let lb_perms = sqlx::query!(
                    "SELECT tlp.permission
                     FROM token_loadbalancer_permission tlp
                     JOIN reservation r ON r.loadbalancer_id = tlp.loadbalancer_id
                     WHERE tlp.token_id = ?1 AND r.id = ?2",
                    token_id,
                    res_id
                )
                .fetch_all(&self.read_pool)
                .await?;

                for perm in lb_perms {
                    let permission: PermissionType = perm.permission.parse().unwrap();
                    if Self::permission_implies(&permission, &required_permission) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Resource::Session(session_id) => {
                // Check direct session permissions
                let session_perms = sqlx::query!(
                    "SELECT permission
                     FROM token_session_permission
                     WHERE token_id = ?1 AND session_id = ?2",
                    token_id,
                    session_id
                )
                .fetch_all(&self.read_pool)
                .await?;

                for perm in session_perms {
                    let permission: PermissionType = perm.permission.parse().unwrap();
                    if Self::permission_implies(&permission, &required_permission) {
                        return Ok(true);
                    }
                }

                // Check if there's a reservation permission that covers this session
                let res_perms = sqlx::query!(
                    "SELECT trp.permission
                     FROM token_reservation_permission trp
                     JOIN session s ON s.reservation_id = trp.reservation_id
                     WHERE trp.token_id = ?1 AND s.id = ?2",
                    token_id,
                    session_id
                )
                .fetch_all(&self.read_pool)
                .await?;

                for perm in res_perms {
                    let permission: PermissionType = perm.permission.parse().unwrap();
                    if Self::permission_implies(&permission, &required_permission) {
                        return Ok(true);
                    }
                }

                // Check if there's a loadbalancer permission that covers this session
                let lb_perms = sqlx::query!(
                    "SELECT tlp.permission
                     FROM token_loadbalancer_permission tlp
                     JOIN reservation r ON r.loadbalancer_id = tlp.loadbalancer_id
                     JOIN session s ON s.reservation_id = r.id
                     WHERE tlp.token_id = ?1 AND s.id = ?2",
                    token_id,
                    session_id
                )
                .fetch_all(&self.read_pool)
                .await?;

                for perm in lb_perms {
                    let permission: PermissionType = perm.permission.parse().unwrap();
                    if Self::permission_implies(&permission, &required_permission) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }

    pub async fn revoke_token(&self, token: &str) -> Result<()> {
        let token_id = self
            .get_token_id(token)
            .await?
            .ok_or_else(|| Error::NotFound("Token not found".to_string()))?;
        self.revoke_token_by_id(token_id).await
    }

    pub async fn revoke_token_by_id(&self, token_id: i64) -> Result<()> {
        // Start a transaction since we need to delete both the token and its children
        let mut tx = self.write_pool.begin().await?;

        // Delete all child tokens recursively
        sqlx::query!(
            r#"
            WITH RECURSIVE token_tree AS (
                SELECT id FROM token WHERE id = ?1
                UNION ALL
                SELECT t.id FROM token t
                INNER JOIN token_tree tt ON t.parent_token_id = tt.id
            )
            DELETE FROM token WHERE id IN (SELECT id FROM token_tree)
            "#,
            token_id
        )
        .execute(&mut *tx)
        .await
        .map_err(Error::Database)?;

        tx.commit().await.map_err(Error::Database)?;
        Ok(())
    }

    pub async fn token_exists(&self, token: &str) -> Result<bool> {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        let result = sqlx::query!("SELECT id FROM token WHERE token_hash = ?1", token_hash)
            .fetch_optional(&self.read_pool)
            .await
            .map_err(Error::Database)?;

        Ok(result.is_some())
    }

    pub async fn remove_permission(&self, token: &str, resource: &Resource) -> Result<()> {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        let token_id = sqlx::query!("SELECT id FROM token WHERE token_hash = ?1", token_hash)
            .fetch_optional(&self.read_pool)
            .await?
            .ok_or_else(|| Error::NotFound("Token not found".to_string()))?
            .id;

        // Delete from the appropriate permission table based on resource type
        match resource {
            Resource::All => {
                sqlx::query!(
                    "DELETE FROM token_global_permission WHERE token_id = ?1",
                    token_id
                )
                .execute(&self.write_pool)
                .await
                .map_err(Error::Database)?;
            }
            Resource::LoadBalancer(lb_id) => {
                sqlx::query!(
                    "DELETE FROM token_loadbalancer_permission
                     WHERE token_id = ?1 AND loadbalancer_id = ?2",
                    token_id,
                    lb_id
                )
                .execute(&self.write_pool)
                .await
                .map_err(Error::Database)?;
            }
            Resource::Reservation(res_id) => {
                sqlx::query!(
                    "DELETE FROM token_reservation_permission
                     WHERE token_id = ?1 AND reservation_id = ?2",
                    token_id,
                    res_id
                )
                .execute(&self.write_pool)
                .await
                .map_err(Error::Database)?;
            }
            Resource::Session(session_id) => {
                sqlx::query!(
                    "DELETE FROM token_session_permission
                     WHERE token_id = ?1 AND session_id = ?2",
                    token_id,
                    session_id
                )
                .execute(&self.write_pool)
                .await
                .map_err(Error::Database)?;
            }
        }

        // Check if any permissions remain across all tables
        let mut tx = self.write_pool.begin().await?;

        let remaining = sqlx::query!(
            "SELECT
                (SELECT COUNT(*) FROM token_global_permission WHERE token_id = ?1) +
                (SELECT COUNT(*) FROM token_loadbalancer_permission WHERE token_id = ?1) +
                (SELECT COUNT(*) FROM token_reservation_permission WHERE token_id = ?1) +
                (SELECT COUNT(*) FROM token_session_permission WHERE token_id = ?1) as count",
            token_id
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(Error::Database)?
        .count;

        if remaining == 0 {
            // If no permissions remain in any table, delete the token
            sqlx::query!("DELETE FROM token WHERE id = ?1", token_id)
                .execute(&mut *tx)
                .await
                .map_err(Error::Database)?;
        }

        tx.commit().await.map_err(Error::Database)?;
        Ok(())
    }

    pub async fn delete_tokens_with_no_permissions(&self) -> Result<()> {
        let mut tx = self.write_pool.begin().await?;

        sqlx::query!(
            r#"
            DELETE FROM token
            WHERE id NOT IN (
                SELECT DISTINCT token_id FROM token_global_permission
                UNION
                SELECT DISTINCT token_id FROM token_loadbalancer_permission
                UNION
                SELECT DISTINCT token_id FROM token_reservation_permission
                UNION
                SELECT DISTINCT token_id FROM token_session_permission
            )
            "#
        )
        .execute(&mut *tx)
        .await
        .map_err(Error::Database)?;

        tx.commit().await.map_err(Error::Database)?;
        Ok(())
    }
}
