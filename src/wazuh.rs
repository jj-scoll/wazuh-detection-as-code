//! Minimal client for the Wazuh 5.0 Content Manager API on the indexer
//! (`/_plugins/_content_manager`), enough to load rules into the test space
//! and run detection-only logtest.
//!
//! TLS is verified against the CA you pass in (the indexer's `root-ca.pem`);
//! there is no option to turn verification off.

use std::sync::Arc;

use base64::Engine;
use serde_json::{Value, json};
use ureq::tls::{Certificate, RootCerts, TlsConfig};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{method} {path}: HTTP {status}: {body}")]
    Api {
        method: &'static str,
        path: String,
        status: u16,
        body: String,
    },
    #[error("{0}")]
    Transport(#[from] ureq::Error),
    #[error("unexpected response to {0}: {1}")]
    Shape(String, Value),
}

pub struct Client {
    base: String,
    auth: String,
    agent: ureq::Agent,
}

impl Client {
    /// `base` is the indexer URL, e.g. `https://127.0.0.1:19200`.
    pub fn new(base: &str, user: &str, password: &str, ca_pem: &[u8]) -> Result<Client, Error> {
        let ca = Certificate::from_pem(ca_pem)?.to_owned();
        let tls = TlsConfig::builder()
            .root_certs(RootCerts::Specific(Arc::new(vec![ca])))
            .build();
        let agent = ureq::Agent::config_builder()
            .tls_config(tls)
            .http_status_as_error(false)
            .build()
            .into();
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        Ok(Client {
            base: format!("{}/_plugins/_content_manager", base.trim_end_matches('/')),
            auth: format!("Basic {token}"),
            agent,
        })
    }

    fn call(&self, method: &'static str, path: &str, body: Option<&Value>) -> Result<Value, Error> {
        let url = format!("{}{path}", self.base);
        let mut resp = match body {
            None => self
                .agent
                .get(&url)
                .header("Authorization", &self.auth)
                .call()?,
            Some(b) => self
                .agent
                .post(&url)
                .header("Authorization", &self.auth)
                .send_json(b)?,
        };
        let status = resp.status().as_u16();
        let text = resp.body_mut().read_to_string()?;
        if !(200..300).contains(&status) {
            return Err(Error::Api {
                method,
                path: path.to_owned(),
                status,
                body: text,
            });
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }

    /// The `message` of a create call is the new resource's ID.
    fn create(&self, path: &str, body: &Value) -> Result<String, Error> {
        let resp = self.call("POST", path, Some(body))?;
        resp["message"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| Error::Shape(format!("POST {path}"), resp))
    }

    /// Create a draft integration; its `title` is the `logsource.product` its
    /// rules must carry.
    pub fn create_integration(&self, title: &str, description: &str) -> Result<String, Error> {
        self.create(
            "/integrations",
            &json!({"resource": {
                "category": "security",
                "enabled": true,
                "metadata": {"title": title, "author": "wazuh-detection-as-code",
                             "description": description, "references": []},
            }}),
        )
    }

    /// Create a draft rule from a converted resource (see `convert::to_wazuh`).
    pub fn create_rule(&self, integration: &str, resource: &Value) -> Result<String, Error> {
        self.create(
            "/rules",
            &json!({"integration": integration, "resource": resource}),
        )
    }

    /// Promote everything pending in draft to the test space: preview, then
    /// execute exactly the changes the preview reported.
    pub fn promote_draft_to_test(&self) -> Result<(), Error> {
        let preview = self.call("GET", "/promote?space=draft", None)?;
        let changes = preview
            .get("changes")
            .ok_or_else(|| Error::Shape("GET /promote".into(), preview.clone()))?;
        self.call(
            "POST",
            "/promote",
            Some(&json!({"space": "draft", "changes": changes})),
        )?;
        Ok(())
    }

    /// Run detection-only logtest for one normalized event against the test
    /// space; returns the Wazuh IDs of the rules that matched.
    pub fn detect(&self, integration: &str, event: &Value) -> Result<Vec<String>, Error> {
        let resp = self.call(
            "POST",
            "/logtest/detection",
            Some(&json!({"space": "test", "integration": integration, "input": event})),
        )?;
        let msg = &resp["message"];
        if msg["status"] != "success" {
            return Err(Error::Shape("POST /logtest/detection".into(), resp));
        }
        Ok(msg["matches"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|m| m["rule"]["id"].as_str().map(str::to_owned))
            .collect())
    }
}
