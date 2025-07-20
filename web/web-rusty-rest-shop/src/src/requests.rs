use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Login {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct Product {
    pub product_id: i32,
    pub count: i32,
}

#[derive(Debug, Deserialize)]
pub struct ProductId {
    pub product_id: i32,
}
