use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum DbRequest {
    Get(DbKey),
    Put(Vec<(DbKey, String)>),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum DbResponse {
    Ok(Option<String>),
    Error(String),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct DbKey {
    pub name: String,
    pub surname: String,
}