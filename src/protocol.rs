use serde::{Serialize, Deserialize};

#[derive(Serialize)]
pub struct InitAuthRequest {
  pub key_id: String,
  pub sign_data: String,
}

#[derive(Deserialize)]
pub struct InitAuthResponse {
  pub request_id: String,
}

#[derive(Serialize)]
pub struct PollAuthRequest {
  pub request_id: String,
}

#[derive(Deserialize)]
pub struct PollAuthResponse {
  pub signature: Option<String>,
}
