use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::FromRow;
use uuid::Uuid;

use crate::{JfrError, Result, model::AuthContext, store::PgStore};

type HmacSha256 = Hmac<Sha256>;
const MANAGED_SCOPES: [&str; 4] = [
    "runtime:read",
    "runtime:write",
    "runtime:validate",
    "admin:keys",
];

#[derive(Debug, Clone, FromRow)]
struct AuthRow {
    key_id: Uuid,
    tenant_id: Uuid,
    key_name: String,
    scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Session {
    pub tenant_id: Uuid,
    pub key_id: Uuid,
    pub key_name: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct ApiKeyRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub prefix: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateApiKey {
    pub name: String,
    pub token: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct ApiKeyEvent {
    pub id: i64,
    pub tenant_id: Uuid,
    pub actor_key_id: Uuid,
    pub target_key_id: Uuid,
    pub action: String,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
}

impl From<AuthContext> for Session {
    fn from(auth: AuthContext) -> Self {
        Self {
            tenant_id: auth.tenant_id,
            key_id: auth.key_id,
            key_name: auth.key_name,
            scopes: auth.scopes,
        }
    }
}

#[derive(Clone)]
pub struct AuthService {
    store: PgStore,
    pepper: SecretString,
}

impl AuthService {
    #[must_use]
    pub const fn new(store: PgStore, pepper: SecretString) -> Self {
        Self { store, pepper }
    }

    pub async fn authenticate(&self, token: &str) -> Result<AuthContext> {
        if token.len() < 32 || token.len() > 512 {
            return Err(JfrError::Unauthorized);
        }
        let digest = digest_key(&self.pepper, token)?;
        let row = sqlx::query_as::<_, AuthRow>(
            r"
            SELECT
                id AS key_id,
                tenant_id,
                name AS key_name,
                scopes
              FROM api_keys
             WHERE secret_hash = $1
               AND revoked_at IS NULL
            ",
        )
        .bind(digest.as_slice())
        .fetch_optional(self.store.pool())
        .await?
        .ok_or(JfrError::Unauthorized)?;
        sqlx::query("UPDATE api_keys SET last_used_at = now() WHERE id = $1")
            .bind(row.key_id)
            .execute(self.store.pool())
            .await?;
        Ok(AuthContext {
            tenant_id: row.tenant_id,
            key_id: row.key_id,
            key_name: row.key_name,
            scopes: row.scopes,
        })
    }

    pub async fn bootstrap(&self, tenant_name: &str, key_name: &str, token: &str) -> Result<()> {
        let mut transaction = self.store.pool().begin().await?;
        let tenant_id = sqlx::query_scalar::<_, Uuid>(
            r"
            INSERT INTO tenants (id, name, created_at)
            VALUES ($1, $2, now())
            ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
            RETURNING id
            ",
        )
        .bind(Uuid::now_v7())
        .bind(tenant_name)
        .fetch_one(&mut *transaction)
        .await?;
        let digest = digest_key(&self.pepper, token)?;
        let prefix = token.chars().take(16).collect::<String>();
        sqlx::query(
            r"
            INSERT INTO api_keys
                (id, tenant_id, name, prefix, secret_hash, scopes, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, now())
            ON CONFLICT (tenant_id, name)
            DO UPDATE SET
                prefix = EXCLUDED.prefix,
                secret_hash = EXCLUDED.secret_hash,
                scopes = EXCLUDED.scopes,
                revoked_at = NULL
            ",
        )
        .bind(Uuid::now_v7())
        .bind(tenant_id)
        .bind(key_name)
        .bind(prefix)
        .bind(digest.as_slice())
        .bind(vec!["*"])
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn list_keys(&self, auth: &AuthContext) -> Result<Vec<ApiKeyRecord>> {
        Ok(sqlx::query_as::<_, ApiKeyRecord>(
            r"
            SELECT id, tenant_id, name, prefix, scopes,
                   created_at, last_used_at, revoked_at
              FROM api_keys
             WHERE tenant_id = $1
             ORDER BY created_at DESC, id DESC
            ",
        )
        .bind(auth.tenant_id)
        .fetch_all(self.store.pool())
        .await?)
    }

    pub async fn list_key_events(&self, auth: &AuthContext) -> Result<Vec<ApiKeyEvent>> {
        Ok(sqlx::query_as::<_, ApiKeyEvent>(
            r"
            SELECT id, tenant_id, actor_key_id, target_key_id,
                   action, metadata, created_at
              FROM api_key_events
             WHERE tenant_id = $1
             ORDER BY id DESC
             LIMIT 1000
            ",
        )
        .bind(auth.tenant_id)
        .fetch_all(self.store.pool())
        .await?)
    }

    pub async fn create_key(
        &self,
        auth: &AuthContext,
        command: CreateApiKey,
    ) -> Result<ApiKeyRecord> {
        let name = command.name.trim();
        if name.is_empty() || name.chars().count() > 128 {
            return Err(JfrError::Validation(
                "key name must contain between 1 and 128 characters".to_owned(),
            ));
        }
        if !(32..=512).contains(&command.token.len()) {
            return Err(JfrError::Validation(
                "API key must contain between 32 and 512 characters".to_owned(),
            ));
        }
        let scopes = validate_managed_scopes(&command.scopes)?;
        let digest = digest_key(&self.pepper, &command.token)?;
        let prefix = command.token.chars().take(16).collect::<String>();
        let key_id = Uuid::now_v7();
        let mut transaction = self.store.pool().begin().await?;
        let record = sqlx::query_as::<_, ApiKeyRecord>(
            r"
            INSERT INTO api_keys
                (id, tenant_id, name, prefix, secret_hash, scopes, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, now())
            ON CONFLICT (tenant_id, name) DO NOTHING
            RETURNING id, tenant_id, name, prefix, scopes,
                      created_at, last_used_at, revoked_at
            ",
        )
        .bind(key_id)
        .bind(auth.tenant_id)
        .bind(name)
        .bind(prefix)
        .bind(digest.as_slice())
        .bind(&scopes)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| JfrError::Conflict(format!("an API key named {name:?} already exists")))?;
        append_key_event(
            &mut transaction,
            auth,
            key_id,
            "api_key.created",
            &json!({"name": name, "scopes": scopes, "prefix": record.prefix}),
        )
        .await?;
        transaction.commit().await?;
        tracing::info!(
            tenant_id = %auth.tenant_id,
            actor_key_id = %auth.key_id,
            target_key_id = %key_id,
            "API key created"
        );
        Ok(record)
    }

    pub async fn revoke_key(&self, auth: &AuthContext, key_id: Uuid) -> Result<ApiKeyRecord> {
        if key_id == auth.key_id {
            return Err(JfrError::Conflict(
                "the currently authenticated API key cannot revoke itself".to_owned(),
            ));
        }
        let mut transaction = self.store.pool().begin().await?;
        let existing = sqlx::query_as::<_, ApiKeyRecord>(
            r"
            SELECT id, tenant_id, name, prefix, scopes,
                   created_at, last_used_at, revoked_at
              FROM api_keys
             WHERE tenant_id = $1 AND id = $2
             FOR UPDATE
            ",
        )
        .bind(auth.tenant_id)
        .bind(key_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| JfrError::NotFound(format!("API key {key_id} was not found")))?;
        if existing.revoked_at.is_some() {
            transaction.commit().await?;
            return Ok(existing);
        }
        let record = sqlx::query_as::<_, ApiKeyRecord>(
            r"
            UPDATE api_keys
               SET revoked_at = now()
             WHERE tenant_id = $1 AND id = $2
            RETURNING id, tenant_id, name, prefix, scopes,
                      created_at, last_used_at, revoked_at
            ",
        )
        .bind(auth.tenant_id)
        .bind(key_id)
        .fetch_one(&mut *transaction)
        .await?;
        append_key_event(
            &mut transaction,
            auth,
            key_id,
            "api_key.revoked",
            &json!({"name": record.name, "prefix": record.prefix}),
        )
        .await?;
        transaction.commit().await?;
        tracing::info!(
            tenant_id = %auth.tenant_id,
            actor_key_id = %auth.key_id,
            target_key_id = %key_id,
            "API key revoked"
        );
        Ok(record)
    }
}

pub fn require_scope(auth: &AuthContext, scope: &str) -> Result<()> {
    if auth.has_scope(scope) {
        Ok(())
    } else {
        Err(JfrError::Forbidden(scope.to_owned()))
    }
}

fn digest_key(pepper: &SecretString, token: &str) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(pepper.expose_secret().as_bytes())
        .map_err(|_| JfrError::Crypto)?;
    mac.update(token.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

fn validate_managed_scopes(scopes: &[String]) -> Result<Vec<String>> {
    let unique: BTreeSet<_> = scopes.iter().map(String::as_str).collect();
    if unique.is_empty() || unique.len() != scopes.len() {
        return Err(JfrError::Validation(
            "scopes must be a non-empty set without duplicates".to_owned(),
        ));
    }
    if let Some(scope) = unique.iter().find(|scope| !MANAGED_SCOPES.contains(scope)) {
        return Err(JfrError::Validation(format!(
            "unsupported managed scope: {scope}"
        )));
    }
    Ok(unique.into_iter().map(str::to_owned).collect())
}

async fn append_key_event(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    auth: &AuthContext,
    target_key_id: Uuid,
    action: &str,
    metadata: &Value,
) -> Result<()> {
    sqlx::query(
        r"
        INSERT INTO api_key_events
            (tenant_id, actor_key_id, target_key_id, action, metadata, created_at)
        VALUES ($1, $2, $3, $4, $5, now())
        ",
    )
    .bind(auth.tenant_id)
    .bind(auth.key_id)
    .bind(target_key_id)
    .bind(action)
    .bind(metadata)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
