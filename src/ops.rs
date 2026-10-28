//! Operator commands that run against the store.

use crate::{crypto::KeyRing, store::Store};

/// Outcome of [`rekey_all`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RekeyReport {
    /// Rows examined.
    pub examined: u64,
    /// Rows re-sealed with the active key.
    pub resealed: u64,
    /// Rows left alone: unreadable with the configured keys, or changed
    /// concurrently while being re-sealed (they are picked up on next use).
    pub skipped: u64,
}

/// Re-seal every stored TOTP secret that is not already under the active
/// key, in batches, so a retired key can be removed from the configuration.
pub async fn rekey_all(store: &Store, keys: &KeyRing) -> anyhow::Result<RekeyReport> {
    const BATCH: i64 = 500;
    let mut report = RekeyReport::default();
    let mut after = String::new();
    loop {
        let batch = store.list_users_after(&after, BATCH).await?;
        let Some(last) = batch.last() else {
            break;
        };
        after = last.id.clone();
        for user in &batch {
            report.examined += 1;
            if user.secret_key_id.as_deref() == Some(keys.active_id()) {
                continue;
            }
            let opened = match keys.open(
                &user.secret_enc,
                user.secret_key_id.as_deref(),
                user.email.as_bytes(),
            ) {
                Ok(opened) => opened,
                Err(err) => {
                    tracing::warn!(user = %user.id, error = %err, "cannot open secret; row left as is");
                    report.skipped += 1;
                    continue;
                }
            };
            let resealed = keys.seal(&opened.plaintext, user.email.as_bytes())?;
            if store
                .reseal_secret(&user.id, &user.secret_enc, &resealed, keys.active_id())
                .await?
            {
                report.resealed += 1;
            } else {
                report.skipped += 1;
            }
        }
    }
    Ok(report)
}
