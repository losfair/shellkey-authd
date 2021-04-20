use anyhow::Result;
use sha2::{Digest, Sha256};
use ssh_agent::{Identity, Response, SSHAgentHandler, error::HandleResult};
use parking_lot::{Mutex, const_mutex};
use thiserror::Error;
use std::time::Duration;

use crate::protocol::{PollAuthRequest, InitAuthRequest, InitAuthResponse, PollAuthResponse};

#[derive(Error, Debug)]
pub enum SshError {
  #[error("bad key blob at line {0}")]
  BadKeyBlobAtLine(usize),
}

pub struct SshConfig {
  pub api_prefix: String,
  pub identities: Vec<SshIdentity>,
}

pub struct SshIdentity {
  pub key_type: String,
  pub key_blob: Vec<u8>,
}

pub fn parse_identities(input: &str) -> Result<Vec<SshIdentity>> {
  let identities: Result<Vec<_>> = input.split("\n")
    .enumerate()
    .map(|(i, x)| (i, x.trim()))
    .filter(|(_, x)| !x.is_empty())
    .map(|(i, x)| (i, x.split(" ").filter(|x| !x.is_empty()).collect::<Vec<&str>>()))
    .filter(|(_, x)| x.len() >= 2)
    .map(|(i, x)| {
      let blob = base64::decode(x[1])
        .map_err(|_| SshError::BadKeyBlobAtLine(i + 1))?;
      Ok(SshIdentity {
        key_type: x[0].to_string(),
        key_blob: blob,
      })
    })
    .collect();
  Ok(identities?)
}

static CONFIG: Mutex<Option<SshConfig>> = const_mutex(None);

pub fn set_config(config: SshConfig) {
  CONFIG.lock().replace(config);
}

pub struct Handler;

impl SSHAgentHandler for Handler {
  fn new() -> Self {
    Self
  }

  fn identities(&mut self) -> HandleResult<Response> {
    trace!("Handler::identities");
    let config = CONFIG.lock();
    let config = config.as_ref().unwrap();

    let identities: Vec<_> = config.identities.iter()
      .map(|x| Identity {
        key_blob: x.key_blob.clone(),
        key_comment: x.key_type.clone(),
      })
      .collect();
    Ok(Response::Identities(identities))
  }

  fn sign_request(&mut self, pubkey: Vec<u8>, data: Vec<u8>, _flags: u32) -> HandleResult<Response> {
    trace!("Handler::sign_request");
    let config_mu = CONFIG.lock();
    let config = config_mu.as_ref().unwrap();
    let identity = config.identities.iter()
      .find(|x| x.key_blob == pubkey)
      .ok_or_else(|| "invalid pubkey")?;
    let key_type = identity.key_type.clone();

    let mut hasher = Sha256::new();
    hasher.update(&pubkey);
    let hash = hasher.finalize();
    let key_id = base64::encode(&hash[..]);

    let api_prefix = config.api_prefix.clone();

    drop(config_mu);

    let client = reqwest::blocking::Client::new();
    let init_req = InitAuthRequest {
      key_id: key_id.clone(),
      challenge: base64::encode(&data),
    };
    let res = client.post(&format!("{}/v1/auth/init", api_prefix))
      .body(serde_json::to_vec(&init_req).unwrap())
      .send()
      .map_err(|_| "init_auth failed")?;
    if !res.status().is_success() {
      return Err("init_auth returned error".into());
    }
    let init_response: InitAuthResponse = serde_json::from_slice(
      &res.bytes().map_err(|_| "init_auth body error")?
    ).map_err(|_| "init_auth response body decode failed")?;

    let poll_req = PollAuthRequest {
      key_id,
      request_id: init_response.request_id.clone(),
    };
    let signature = loop {
      std::thread::sleep(Duration::from_secs(3));
      let res = client.post(&format!("{}/v1/auth/poll", api_prefix))
        .body(serde_json::to_vec(&poll_req).unwrap())
        .send()
        .map_err(|_| "poll_auth failed")?;
      if !res.status().is_success() {
        return Err("poll_auth returned error".into());
      }
      let poll_response: PollAuthResponse = serde_json::from_slice(
        &res.bytes().map_err(|_| "poll_auth body error")?
      ).map_err(|_| "poll_auth response body decode failed")?;
      if let Some(x) = poll_response.signature {
        break base64::decode(&x)
          .map_err(|_| "poll_auth returned invalid signature")?
      }
    };
    Ok(Response::SignResponse {
      algo_name: key_type,
      signature,
    })
  }
}
