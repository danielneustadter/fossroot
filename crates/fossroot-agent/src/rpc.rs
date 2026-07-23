//! Agent RPC surface. The spike exposes a liveness check and a read-only trust
//! report; signing (#3) and browser-session remediation (#2) will add methods
//! here, each gated behind explicit per-action user consent.

use serde::{Deserialize, Serialize};

use fossroot_core::store::{platform, Location, StoreKind, SystemStore, TrustStore};
use fossroot_core::{diff, Bundle, CertStatus, Group};

#[derive(Debug, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Request {
    /// Liveness / version handshake.
    Ping,
    /// Read-only DoD-PKI trust coverage for a group (default: dod).
    TrustStatus {
        #[serde(default)]
        group: Option<String>,
    },
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Response {
    Ok(serde_json::Value),
    Err { ok: bool, error: String },
}

impl Response {
    fn err(msg: impl Into<String>) -> Response {
        Response::Err {
            ok: false,
            error: msg.into(),
        }
    }
}

/// Dispatch a single request to a JSON response. Never panics — every failure
/// becomes an `{ ok: false, error }` object the extension can render.
pub fn handle(req: Request) -> Response {
    match req {
        Request::Ping => Response::Ok(serde_json::json!({
            "ok": true,
            "method": "ping",
            "pong": true,
            "agent_version": env!("CARGO_PKG_VERSION"),
        })),
        Request::TrustStatus { group } => trust_status(group.as_deref()),
    }
}

fn trust_status(group_token: Option<&str>) -> Response {
    let group = match group_token {
        None => Group::Dod,
        Some(t) => match Group::from_token(t) {
            Some(g) => g,
            None => return Response::err(format!("unknown group '{t}'")),
        },
    };

    let bundle = match Bundle::fetch_group(group) {
        Ok(b) => b,
        Err(e) => return Response::err(format!("fetch/verify failed: {e}")),
    };

    let now = now_unix();
    let store = platform();
    let mut per_location = Vec::new();
    for location in [Location::CurrentUser, Location::LocalMachine] {
        let in_root = match store.list(SystemStore {
            location,
            kind: StoreKind::Root,
        }) {
            Ok(v) => v,
            Err(e) => return Response::err(format!("reading trust store: {e}")),
        };
        let in_ca = match store.list(SystemStore {
            location,
            kind: StoreKind::Ca,
        }) {
            Ok(v) => v,
            Err(e) => return Response::err(format!("reading trust store: {e}")),
        };
        per_location.push(diff::diff(&bundle.certs, &in_root, &in_ca, now));
    }
    let machine = per_location.pop().unwrap();
    let user = per_location.pop().unwrap();

    // A cert is effectively trusted if either store has it.
    let effective = user
        .entries
        .iter()
        .zip(machine.entries.iter())
        .filter(|(u, m)| u.status == CertStatus::Installed || m.status == CertStatus::Installed)
        .count();
    let usable_total = user.installed + user.missing;

    Response::Ok(serde_json::json!({
        "ok": true,
        "method": "trust_status",
        "group": bundle.group,
        "group_name": group.name(),
        "version": bundle.version,
        "manifest_signed": bundle.verify.manifest_signed,
        "effective": effective,
        "usable_total": usable_total,
        "user_missing": user.missing,
        "machine_missing": machine.missing,
        "is_test_pki": group.is_test_pki(),
    }))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_dispatches() {
        let req: Request = serde_json::from_str(r#"{"method":"ping"}"#).unwrap();
        let resp = handle(req);
        let v = match resp {
            Response::Ok(v) => v,
            Response::Err { .. } => panic!("ping should succeed"),
        };
        assert_eq!(v["pong"], true);
        assert_eq!(v["agent_version"], env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn unknown_group_is_error_not_panic() {
        let req: Request =
            serde_json::from_str(r#"{"method":"trust_status","group":"bogus"}"#).unwrap();
        match handle(req) {
            Response::Err { ok, error } => {
                assert!(!ok);
                assert!(error.contains("bogus"));
            }
            Response::Ok(_) => panic!("bogus group should error"),
        }
    }

    #[test]
    fn unknown_method_fails_to_parse() {
        assert!(serde_json::from_str::<Request>(r#"{"method":"launch_missiles"}"#).is_err());
    }
}
