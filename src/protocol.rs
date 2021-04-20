use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct InitAuthRequest {
  pub key_id: String,
  pub challenge: String,
}

#[derive(Deserialize)]
pub struct InitAuthResponse {
  pub request_id: String,
}

#[derive(Serialize)]
pub struct PollAuthRequest {
  pub key_id: String,
  pub request_id: String,
}

#[derive(Deserialize)]
pub struct PollAuthResponse {
  pub signature: Option<String>,
}
