use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    JfrError, Result,
    model::{AuditReport, EventRecord},
};

pub const HASH_BYTES: usize = 32;
pub const GENESIS_HASH: [u8; HASH_BYTES] = [0; HASH_BYTES];

#[derive(Debug, Serialize)]
struct EventMaterial<'a> {
    case_id: Uuid,
    sequence: i64,
    tenant_id: Uuid,
    event_type: &'a str,
    payload: &'a Value,
    previous_hash: String,
    actor_key_id: Uuid,
    created_at: DateTime<Utc>,
}

pub fn event_hash(
    case_id: Uuid,
    sequence: i64,
    tenant_id: Uuid,
    event_type: &str,
    payload: &Value,
    previous_hash: &[u8],
    actor_key_id: Uuid,
    created_at: DateTime<Utc>,
) -> Result<[u8; HASH_BYTES]> {
    if previous_hash.len() != HASH_BYTES {
        return Err(JfrError::Crypto);
    }
    let material = EventMaterial {
        case_id,
        sequence,
        tenant_id,
        event_type,
        payload,
        previous_hash: hex::encode(previous_hash),
        actor_key_id,
        created_at,
    };
    let canonical = serde_jcs::to_vec(&material).map_err(|_| JfrError::Crypto)?;
    Ok(Sha256::digest(canonical).into())
}

#[must_use]
pub fn verify_events(
    events: &[EventRecord],
    committed_count: i64,
    committed_head: &[u8],
) -> AuditReport {
    let mut previous = GENESIS_HASH.to_vec();
    let mut checked = 0_i64;
    for event in events {
        let expected_sequence = checked + 1;
        if event.sequence != expected_sequence {
            return AuditReport {
                valid: false,
                checked_events: checked,
                failed_sequence: Some(event.sequence),
                reason: Some(format!(
                    "expected sequence {expected_sequence}, found {}",
                    event.sequence
                )),
                head_hash: hex::encode(previous),
            };
        }
        if event.previous_hash != previous {
            return AuditReport {
                valid: false,
                checked_events: checked,
                failed_sequence: Some(event.sequence),
                reason: Some("previous hash does not match the event chain".to_owned()),
                head_hash: hex::encode(previous),
            };
        }
        let Ok(expected) = event_hash(
            event.case_id,
            event.sequence,
            event.tenant_id,
            &event.event_type,
            &event.payload,
            &event.previous_hash,
            event.actor_key_id,
            event.created_at,
        ) else {
            return AuditReport {
                valid: false,
                checked_events: checked,
                failed_sequence: Some(event.sequence),
                reason: Some("event could not be canonicalized".to_owned()),
                head_hash: hex::encode(previous),
            };
        };
        if event.event_hash != expected {
            return AuditReport {
                valid: false,
                checked_events: checked,
                failed_sequence: Some(event.sequence),
                reason: Some("event content does not match its hash".to_owned()),
                head_hash: hex::encode(previous),
            };
        }
        previous.clone_from(&event.event_hash);
        checked += 1;
    }
    if i64::try_from(events.len()).ok() != Some(committed_count) {
        return AuditReport {
            valid: false,
            checked_events: checked,
            failed_sequence: None,
            reason: Some("ledger length does not match the committed count".to_owned()),
            head_hash: hex::encode(previous),
        };
    }
    if previous != committed_head {
        return AuditReport {
            valid: false,
            checked_events: committed_count,
            failed_sequence: None,
            reason: Some("ledger head does not match the committed hash".to_owned()),
            head_hash: hex::encode(previous),
        };
    }
    AuditReport {
        valid: true,
        checked_events: committed_count,
        failed_sequence: None,
        reason: None,
        head_hash: hex::encode(previous),
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    #[test]
    fn event_hash_is_deterministic_and_content_sensitive() {
        let case_id = Uuid::from_u128(1);
        let tenant_id = Uuid::from_u128(2);
        let actor_id = Uuid::from_u128(3);
        let created_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let first = event_hash(
            case_id,
            1,
            tenant_id,
            "case.created",
            &json!({"name": "fiber"}),
            &GENESIS_HASH,
            actor_id,
            created_at,
        )
        .unwrap();
        let second = event_hash(
            case_id,
            1,
            tenant_id,
            "case.created",
            &json!({"name": "fiber"}),
            &GENESIS_HASH,
            actor_id,
            created_at,
        )
        .unwrap();
        let changed = event_hash(
            case_id,
            1,
            tenant_id,
            "case.created",
            &json!({"name": "other"}),
            &GENESIS_HASH,
            actor_id,
            created_at,
        )
        .unwrap();

        assert_eq!(first, second);
        assert_ne!(first, changed);
    }

    #[test]
    fn verifier_rejects_sequence_gaps_and_payload_tampering() {
        let case_id = Uuid::from_u128(10);
        let tenant_id = Uuid::from_u128(20);
        let actor_id = Uuid::from_u128(30);
        let created_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let first_payload = json!({"name": "fiber"});
        let first_hash = event_hash(
            case_id,
            1,
            tenant_id,
            "case.created",
            &first_payload,
            &GENESIS_HASH,
            actor_id,
            created_at,
        )
        .unwrap();
        let second_payload = json!({"branch_id": "branch-a"});
        let second_hash = event_hash(
            case_id,
            2,
            tenant_id,
            "branch.proposed",
            &second_payload,
            &first_hash,
            actor_id,
            created_at,
        )
        .unwrap();
        let first = EventRecord {
            case_id,
            sequence: 1,
            tenant_id,
            event_type: "case.created".to_owned(),
            payload: first_payload,
            previous_hash: GENESIS_HASH.to_vec(),
            event_hash: first_hash.to_vec(),
            actor_key_id: actor_id,
            created_at,
        };
        let second = EventRecord {
            case_id,
            sequence: 2,
            tenant_id,
            event_type: "branch.proposed".to_owned(),
            payload: second_payload,
            previous_hash: first_hash.to_vec(),
            event_hash: second_hash.to_vec(),
            actor_key_id: actor_id,
            created_at,
        };
        let valid = verify_events(&[first.clone(), second.clone()], 2, &second_hash);
        assert!(valid.valid);

        let mut gap = second.clone();
        gap.sequence = 3;
        assert!(!verify_events(&[first.clone(), gap], 2, &second_hash).valid);

        let mut tampered = second;
        tampered.payload = json!({"branch_id": "branch-b"});
        assert!(!verify_events(&[first, tampered], 2, &second_hash).valid);
    }
}
