use serde::Serialize;

use crate::db;

#[derive(Debug, Serialize)]
pub struct User {
    pub username: String,
    pub balance: i64,
}

impl From<db::User> for User {
    fn from(value: db::User) -> Self {
        Self {
            username: value.username,
            balance: value.balance,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Product {
    pub product_id: i32,
    pub name: String,
    pub price: i64,
    pub image: String,
}

impl From<db::Product> for Product {
    fn from(value: db::Product) -> Self {
        Self {
            product_id: value.product_id,
            name: value.name,
            price: value.price,
            image: value.image,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Owned {
    pub product_id: i32,
    pub count: i32,
}

#[derive(Debug, Serialize)]
pub struct UserState {
    pub user: User,
    pub owned: Vec<Owned>,
    pub cart: Vec<Owned>,
}

impl From<db::UserState> for UserState {
    fn from(value: db::UserState) -> Self {
        Self {
            user: value.user.into(),
            owned: value
                .owned
                .into_iter()
                .map(|p| Owned {
                    product_id: p.product_id,
                    count: p.count,
                })
                .collect(),
            cart: value
                .cart
                .into_iter()
                .map(|p| Owned {
                    product_id: p.product_id,
                    count: p.count,
                })
                .collect(),
        }
    }
}
