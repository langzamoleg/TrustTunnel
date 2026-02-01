use crate::authentication::Authenticator;
use crate::{authentication, log_utils};
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine;
use std::time::{SystemTime, UNIX_EPOCH};
use toml_edit::{Document, Item};

pub struct FileBasedAuthenticator {
    credentials_file_path: String,
}

impl FileBasedAuthenticator {
    pub fn new(credentials_file_path: String) -> Self {
        Self {
            credentials_file_path,
        }
    }

    fn now_unix_ts() -> Option<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs())
    }

    fn is_valid_client(
        doc: &Document,
        source: &authentication::Source<'_>,
        now: Option<u64>,
    ) -> bool {
        let clients = match doc.get("client").and_then(Item::as_array_of_tables) {
            Some(x) => x,
            None => return false,
        };

        for client in clients.iter() {
            let username = client.get("username").and_then(Item::as_str);
            let password = client.get("password").and_then(Item::as_str);

            let (Some(username), Some(password)) = (username, password) else {
                continue;
            };

            if let Some(valid_till) = client
                .get("valid_till")
                .and_then(Item::as_integer)
                .and_then(|x| u64::try_from(x).ok())
            {
                if let Some(now) = now {
                    if now > valid_till {
                        continue;
                    }
                }
            }

            match source {
                authentication::Source::ProxyBasic(auth_str) => {
                    let expected = BASE64_ENGINE.encode(format!("{}:{}", username, password));
                    if expected == auth_str.as_ref() {
                        return true;
                    }
                }
                authentication::Source::Sni(creds) => {
                    if creds.as_ref() == username {
                        return true;
                    }
                }
            }
        }

        false
    }
}

impl Authenticator for FileBasedAuthenticator {
    fn authenticate(
        &self,
        source: &authentication::Source<'_>,
        _log_id: &log_utils::IdChain<u64>,
    ) -> authentication::Status {
        let content = match std::fs::read_to_string(&self.credentials_file_path) {
            Ok(x) => x,
            Err(_) => return authentication::Status::Reject,
        };

        let doc: Document = match content.parse() {
            Ok(x) => x,
            Err(_) => return authentication::Status::Reject,
        };

        let now = Self::now_unix_ts();
        if Self::is_valid_client(&doc, source, now) {
            authentication::Status::Pass
        } else {
            authentication::Status::Reject
        }
    }
}
