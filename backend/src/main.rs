use axum::{Json, routing::post, Router,};
use serde::{Deserialize, Serialize,};
use tokio::net::TcpListener;

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    success: bool,
}

async fn handle_login(Json(data): Json<LoginRequest>) -> Json<LoginResponse> {
    let ok: bool = &data.username == "Aaron";
    println!("Got request, username = {}, returning {}", data.username, ok);
    Json(LoginResponse {success: ok})
}

#[tokio::main]
async fn main() {
    let app: Router = Router::new()
        .route("/login", post(handle_login));
    
    let listener: TcpListener = TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();

    axum::serve(listener, app).await.unwrap();
}
