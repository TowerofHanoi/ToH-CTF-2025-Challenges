use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::prelude::*;
use rand::rng;
use sqlx::sqlite::SqlitePool as Pool;
use sqlx::Error;
use sqlx::{Connection, Executor, FromRow, Sqlite, Transaction};

const MIGRATIONS: [&str; 2] = [
    r#"
CREATE TABLE user (
    user_id INTEGER PRIMARY KEY,
    username VARCHAR(32) NOT NULL,
    credential BLOB NOT NULL,
    balance INTEGER NOT NULL
);
CREATE TABLE session (
    session_id BLOB PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES user(user_id) ON DELETE CASCADE
);
CREATE TABLE product (
    product_id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    price BIGINT NOT NULL,
    image TEXT NOT NULL
);
CREATE TABLE owned (
    user_id INTEGER REFERENCES user(user_id) ON DELETE CASCADE,
    product_id INTEGER REFERENCES product(product_id) ON DELETE CASCADE,
    count INT NOT NULL,
    PRIMARY KEY(user_id, product_id)
);
CREATE TABLE cart (
    session_id BLOB REFERENCES session(session_id) ON DELETE CASCADE,
    product_id INTEGER REFERENCES product(product_id) ON DELETE CASCADE,
    count INT NOT NULL,
    price BIGINT NOT NULL,
    PRIMARY KEY(session_id, product_id)
);
"#,
    r#"
INSERT INTO product (product_id, name, price, image) VALUES
    (0, "Magic Image 0", 75, "img/img0.webp"),
    (1, "Magic Image 1", 75, "img/img1.webp"),
    (2, "Magic Image 2", 120, "img/img2.webp"),
    (3, "Magic Image 3", 160, "img/img3.webp"),
    (4, "Magic Image 4", 200, "img/img4.webp"),
    (5, "Magic Image 5", 250, "img/img5.webp");
"#,
];

const SIGNUP_BONUS: i64 = 250;

#[allow(unused)]
#[derive(FromRow)]
pub struct User {
    pub user_id: i32,
    pub username: String,
    pub credential: Vec<u8>,
    pub balance: i64,
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("user_id", &self.user_id)
            .field("username", &self.username)
            .field("credential", &"<REDACTED>")
            .field("balance", &self.balance)
            .finish()
    }
}

#[allow(unused)]
#[derive(Debug, FromRow)]
pub struct Session {
    pub session_id: Vec<u8>,
    pub user_id: i32,
}
#[derive(Debug, FromRow)]
pub struct Product {
    pub product_id: i32,
    pub name: String,
    pub price: i64,
    pub image: String,
}
#[allow(unused)]
#[derive(Debug, FromRow)]
pub struct Owned {
    pub user_id: i32,
    pub product_id: i32,
    pub count: i32,
}
#[allow(unused)]
#[derive(Debug, FromRow)]
pub struct CartItem {
    pub session_id: Vec<u8>,
    pub product_id: i32,
    pub count: i32,
    pub price: i64,
}

pub struct UserState {
    pub user: User,
    pub owned: Vec<Owned>,
    pub cart: Vec<CartItem>,
}

pub async fn setup(db: &Pool) -> Result<(), sqlx::Error> {
    let mut conn = db.acquire().await?;
    conn.execute("CREATE TABLE IF NOT EXISTS migration (id INT PRIMARY KEY);")
        .await?;

    for (i, m) in MIGRATIONS.iter().enumerate() {
        let i = i as i32;
        let o = sqlx::query("SELECT id FROM migration WHERE id = ?1")
            .bind(i)
            .fetch_optional(conn.as_mut())
            .await?;
        if o.is_none() {
            conn.execute(*m).await?;
            sqlx::query("INSERT INTO migration (id) VALUES (?1)")
                .bind(i)
                .execute(conn.as_mut())
                .await?;
        }
    }

    Ok(())
}

pub async fn register(db: &Pool, username: String, password: String) -> Result<bool, sqlx::Error> {
    let mut conn = db.acquire().await?;
    let mut tx = conn.begin().await?;

    let user = sqlx::query_as::<_, User>("SELECT * FROM user WHERE username = ?1")
        .bind(&username)
        .fetch_optional(tx.as_mut())
        .await?;

    if user.is_none() {
        let cred = password::store_password(&username, &password);
        sqlx::query("INSERT INTO user (username, credential, balance) VALUES (?1, ?2, ?3)")
            .bind(username)
            .bind(cred)
            .bind(SIGNUP_BONUS)
            .execute(tx.as_mut())
            .await?;
        tx.commit().await?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub async fn login(
    db: &Pool,
    username: String,
    password: String,
) -> Result<Option<Session>, Error> {
    let mut conn = db.acquire().await?;

    let user = sqlx::query_as::<_, User>("SELECT * FROM user WHERE username = ?1")
        .bind(&username)
        .fetch_one(conn.as_mut())
        .await?;

    if !password::verify_password(&username, &password, &user.credential) {
        tracing::info!("Failed login for '{username}'");
        return Ok(None);
    }

    tracing::info!("{user:?}");

    // Generate and save new session
    let session_id: [u8; 32] = rng().random();
    sqlx::query("INSERT INTO session (session_id, user_id) VALUES (?1, ?2)")
        .bind(session_id.to_vec())
        .bind(user.user_id)
        .execute(conn.as_mut())
        .await?;

    Ok(Some(Session {
        session_id: session_id.into(),
        user_id: user.user_id,
    }))
}

pub async fn logout(db: &Pool, user_id: i32) -> Result<(), Error> {
    let mut conn = db.acquire().await?;
    sqlx::query("DELETE FROM session WHERE user_id = ?1")
        .bind(user_id)
        .execute(conn.as_mut())
        .await?;
    Ok(())
}

pub async fn user_data(db: &Pool, session_id: Vec<u8>) -> Result<UserState, Error> {
    let mut conn = db.acquire().await?;
    let mut tx = conn.begin().await?;
    user_state(&mut tx, session_id).await
}

async fn user_state(
    tx: &mut Transaction<'_, Sqlite>,
    session_id: Vec<u8>,
) -> Result<UserState, Error> {
    let session = sqlx::query_as::<_, Session>("SELECT * FROM session WHERE session_id = ?1")
        .bind(session_id)
        .fetch_one(tx.as_mut())
        .await?;

    let user = sqlx::query_as::<_, User>("SELECT * FROM user WHERE user_id = ?1")
        .bind(session.user_id)
        .fetch_one(tx.as_mut())
        .await?;

    let owned = sqlx::query_as::<_, Owned>("SELECT * FROM owned WHERE user_id = ?1")
        .bind(session.user_id)
        .fetch_all(tx.as_mut())
        .await?;

    let cart = sqlx::query_as::<_, CartItem>("SELECT * FROM cart WHERE session_id = ?1")
        .bind(session.session_id)
        .fetch_all(tx.as_mut())
        .await?;

    Ok(UserState { user, owned, cart })
}

pub async fn products(db: &Pool) -> Result<Vec<Product>, Error> {
    let mut conn = db.acquire().await?;
    sqlx::query_as::<_, Product>("SELECT * FROM product")
        .fetch_all(conn.as_mut())
        .await
}

pub async fn add_cart(
    db: &Pool,
    session_id: Vec<u8>,
    product_id: i32,
    count: i32,
) -> Result<bool, Error> {
    let mut conn = db.acquire().await?;
    let mut tx = conn.begin().await?;

    let UserState { user, cart, .. } = user_state(&mut tx, session_id.clone()).await?;

    let product = sqlx::query_as::<_, Product>("SELECT * FROM product WHERE product_id = ?1")
        .bind(product_id)
        .fetch_one(tx.as_mut())
        .await?;

    let balance = user.balance;
    let cart_value = cart.iter().map(|e| e.price * e.count as i64).sum::<i64>();
    let cost = product.price * count as i64;

    tracing::info!("{product:?}");
    tracing::info!("b: {balance}, c: {cost}, cv: {cart_value}");

    if balance < 0 || cart_value < 0 || cost < 0 {
        return Ok(false);
    }

    if cost + cart_value <= balance {
        if cart.iter().any(|e| e.product_id == product_id) {
            sqlx::query(
                "UPDATE cart SET count = count + ?1 WHERE session_id = ?2 AND product_id = ?3",
            )
            .bind(count)
            .bind(session_id)
            .bind(product_id)
            .execute(tx.as_mut())
            .await?;
        } else {
            tracing::info!(
                "{}, {}, {}, {}",
                BASE64.encode(&session_id),
                product_id,
                count,
                product.price
            );
            sqlx::query(
                "INSERT INTO cart (session_id, product_id, count, price) VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(session_id)
            .bind(product_id)
            .bind(count)
            .bind(product.price)
            .execute(tx.as_mut())
            .await?;
        }

        tx.commit().await?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub async fn remove_cart(db: &Pool, session_id: Vec<u8>, product_id: i32) -> Result<(), Error> {
    let mut conn = db.acquire().await?;

    sqlx::query("DELETE FROM cart WHERE session_id = ?1 AND product_id = ?2")
        .bind(session_id)
        .bind(product_id)
        .execute(conn.as_mut())
        .await?;

    Ok(())
}

pub async fn confirm_purchase(db: &Pool, session_id: Vec<u8>) -> Result<(), Error> {
    let mut conn = db.acquire().await?;
    let mut tx = conn.begin().await?;

    let UserState { user, owned, cart } = user_state(&mut tx, session_id.clone()).await?;

    let cart_value = cart.iter().map(|e| e.price * e.count as i64).sum::<i64>();

    sqlx::query("UPDATE user SET balance = balance - ?1 WHERE user_id = ?2")
        .bind(cart_value)
        .bind(user.user_id)
        .execute(tx.as_mut())
        .await?;

    sqlx::query("DELETE FROM cart WHERE session_id = ?1")
        .bind(session_id)
        .execute(tx.as_mut())
        .await?;

    for item in cart {
        if owned.iter().any(|e| e.product_id == item.product_id) {
            sqlx::query(
                "UPDATE owned SET count = count + ?1 WHERE user_id = ?2 AND product_id = ?3",
            )
            .bind(item.count)
            .bind(user.user_id)
            .bind(item.product_id)
            .execute(tx.as_mut())
            .await?;
        } else {
            sqlx::query("INSERT INTO owned (user_id, product_id, count) VALUES (?1, ?2, ?3)")
                .bind(user.user_id)
                .bind(item.product_id)
                .bind(item.count)
                .execute(tx.as_mut())
                .await?;
        }
    }

    tx.commit().await?;

    Ok(())
}

mod password {
    use std::num::NonZeroU32;

    use ring::{digest, pbkdf2};

    static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
    const PBKDF2_ITER: NonZeroU32 = NonZeroU32::new(10_000).unwrap(); // SAFETY: Do I need to explain?
    const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;
    pub type Credential = [u8; CREDENTIAL_LEN];

    const PEPPER: [u8; 16] = [
        // This value was generated from a secure PRNG. (And totally not copied from an example 🫥)
        0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52, 0x24, 0xf2, 0x27, 0xd1, 0xfe, 0x39, 0x01,
        0x8a,
    ];

    pub fn store_password(username: &str, password: &str) -> Vec<u8> {
        let salt = salt(username);
        let mut to_store: Credential = [0u8; CREDENTIAL_LEN];
        pbkdf2::derive(
            PBKDF2_ALG,
            PBKDF2_ITER,
            &salt,
            password.as_bytes(),
            &mut to_store,
        );

        to_store.to_vec()
    }

    pub fn verify_password(username: &str, attempted_password: &str, actual: &[u8]) -> bool {
        let salt = salt(username);
        pbkdf2::verify(
            PBKDF2_ALG,
            PBKDF2_ITER,
            &salt,
            attempted_password.as_bytes(),
            actual,
        )
        .is_ok()
    }

    fn salt(username: &str) -> Vec<u8> {
        let mut salt = Vec::with_capacity(PEPPER.len() + username.len());
        salt.extend(username.as_bytes());
        salt.extend(PEPPER.as_ref());
        salt
    }
}
