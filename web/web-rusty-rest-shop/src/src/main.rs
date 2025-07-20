//! Run with
//!
//! ```not_rust
//! cargo run --release
//! ```

use axum::{
    extract::{FromRequestParts, Json, State},
    http::{header, request::Parts, HeaderMap, StatusCode},
    routing::{get, post},
    Router,
};
use axum_extra::extract::CookieJar;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use db::UserState;
use std::{collections::HashSet, net::SocketAddr, str::FromStr};

use sqlx::sqlite::{SqliteConnectOptions, SqlitePool as Pool, SqlitePoolOptions};

use requests::*;

mod db;
mod requests;
mod responses;

const SESSION_COOKIE: &str = "session_id";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let conn_opt = SqliteConnectOptions::from_str("sqlite:db/db.sqlite3")
        .unwrap()
        .create_if_missing(true);

    // set up connection pool
    let pool = SqlitePoolOptions::new()
        .connect_with(conn_opt)
        .await
        .unwrap();

    db::setup(&pool).await.unwrap();

    // build our application with some routes
    let app = Router::new()
        .route("/register", post(register_post))
        .route("/login", post(login_post))
        .route("/logout", post(logout_post))
        .route("/session", get(session_get))
        .route("/products", get(products_get))
        .route("/flag", get(flag_get))
        .route("/cart/add", post(add_to_cart_post))
        .route("/cart/rem", post(rem_from_cart_post))
        .route("/cart/confirm", post(confirm_purchase_post))
        .with_state(pool);

    // run it with hyper
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::debug!("listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

struct Session(Vec<u8>);

impl<S> FromRequestParts<S> for Session
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|_| (StatusCode::FORBIDDEN, "No Cookies! 🍪"))?;

        jar.get(SESSION_COOKIE)
            .inspect(|c| tracing::info!("{c}"))
            .and_then(|c| BASE64.decode(c.value()).ok())
            .map(Session)
            .ok_or((
                StatusCode::FORBIDDEN,
                "Missing or invalid session cookie! 🍪",
            ))
    }
}

async fn register_post(
    State(db): State<Pool>,
    Json(login): Json<Login>,
) -> Result<StatusCode, (StatusCode, String)> {
    if login.username.len() < 3 || login.password.len() < 3 {
        return Err((StatusCode::BAD_REQUEST, "Username or password too short! 🙅🏻‍♂️\nUse at least 3 characters come on it's not a lot 😡".into(),));
    }

    let result = db::register(&db, login.username, login.password)
        .await
        .map_err(internal_error)?;

    if result {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::FORBIDDEN, "Useraname already taken! 🙅🏻‍♂️".into()))
    }
}

async fn login_post(
    State(db): State<Pool>,
    Json(login): Json<Login>,
) -> Result<(StatusCode, HeaderMap), (StatusCode, String)> {
    let Login { username, password } = login;
    let session = db::login(&db, username, password)
        .await
        .map_err(internal_error)?;

    match session {
        None => Err((
            StatusCode::FORBIDDEN,
            "Wrong username or password! 🙅🏻‍♂️".into(),
        )),
        Some(session) => {
            let mut headers = HeaderMap::new();
            headers.insert(header::LOCATION, "/home".parse().unwrap());
            headers.insert(
                header::SET_COOKIE,
                format!(
                    "{SESSION_COOKIE}={}; Max-Age=3600; HttpOnly; SameSite=Lax; Path=/",
                    BASE64.encode(session.session_id)
                )
                .parse()
                .unwrap(),
            );
            Ok((StatusCode::OK, headers))
        }
    }
}

async fn logout_post(
    State(db): State<Pool>,
    Session(session_id): Session,
) -> Result<(StatusCode, HeaderMap), (StatusCode, String)> {
    let UserState { user, .. } = db::user_data(&db, session_id)
        .await
        .map_err(internal_error)?;

    db::logout(&db, user.user_id)
        .await
        .map_err(internal_error)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        format!("{SESSION_COOKIE}=; Max-Age=-1; Secure; HttpOnly; SameSite=Strict")
            .parse()
            .unwrap(),
    );
    Ok((StatusCode::OK, headers))
}

async fn session_get(
    State(db): State<Pool>,
    Session(session_id): Session,
) -> Result<Json<responses::UserState>, (StatusCode, String)> {
    let user_state = db::user_data(&db, session_id)
        .await
        .map_err(internal_error)?;
    Ok(Json(responses::UserState::from(user_state)))
}

async fn products_get(
    State(db): State<Pool>,
) -> Result<Json<Vec<responses::Product>>, (StatusCode, String)> {
    let products = db::products(&db).await.map_err(internal_error)?;
    Ok(Json(products.into_iter().map(|p| p.into()).collect()))
}

async fn add_to_cart_post(
    State(db): State<Pool>,
    Session(session_id): Session,
    Json(product): Json<Product>,
) -> Result<Json<bool>, (StatusCode, String)> {
    let result = db::add_cart(&db, session_id, product.product_id, product.count)
        .await
        .map_err(bad_request)?;

    Ok(Json(result))
}

async fn rem_from_cart_post(
    State(db): State<Pool>,
    Session(session_id): Session,
    Json(product): Json<ProductId>,
) -> Result<String, (StatusCode, String)> {
    db::remove_cart(&db, session_id, product.product_id)
        .await
        .map_err(bad_request)?;
    Ok("Ok!".into())
}

async fn confirm_purchase_post(
    State(db): State<Pool>,
    Session(session_id): Session,
) -> Result<String, (StatusCode, String)> {
    db::confirm_purchase(&db, session_id)
        .await
        .map_err(bad_request)?;
    Ok("Ok!".into())
}

async fn flag_get(
    State(db): State<Pool>,
    Session(session_id): Session,
) -> Result<String, (StatusCode, String)> {
    let UserState { owned, .. } = db::user_data(&db, session_id)
        .await
        .map_err(internal_error)?;

    let products = db::products(&db).await.map_err(internal_error)?;
    let owned_pid = owned.iter().map(|o| o.product_id).collect::<HashSet<_>>(); // n^2 bad!
    if products.iter().all(|p| owned_pid.contains(&p.product_id)) {
        Ok(read_flag()?)
    } else {
        Err((
            StatusCode::FORBIDDEN,
            "No one is impressed with your digital art collection 👺\n\nYou need all pieces for some proper clout! 👽".into(),
        ))
    }
}

fn read_flag() -> Result<String, (StatusCode, String)> {
    let flag = std::io::read_to_string(std::fs::File::open("flag.txt").map_err(internal_error)?)
        .map_err(internal_error)?;
    Ok(flag)
}
/// Utility function for mapping any error into a `500 Internal Server Error`
/// response.
fn internal_error<E>(err: E) -> (StatusCode, String)
where
    E: std::error::Error,
{
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("API ERROR: {}", err),
    )
}

/// Utility function for mapping any error into a `500 Internal Server Error`
/// response.
fn bad_request<E>(err: E) -> (StatusCode, String)
where
    E: std::error::Error,
{
    (StatusCode::BAD_REQUEST, err.to_string())
}
