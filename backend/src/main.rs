mod includes;
use crate::includes::*;

// Structs to parse data
#[derive(Clone)]
struct AppState {
    db_pool: MySqlPool,
}

#[derive(Deserialize)]
struct SignupRequest {
    username: String,
    password: String,
    email: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    username_or_email: String,
    password: String,
}

#[derive(Serialize)]
struct Response {
    success: bool,
    message: String,
}

async fn handle_signup(
    State(state): State<AppState>,
    Json(data): Json<SignupRequest>,
) -> Json<Response> {
    // Get data from the request
    let username: String = data.username;
    let email: String = data.email;
    let password: String = data.password;
    println!("Got query for {}", &username);

    // Enforce constraints
    if username.chars().count() > 20 {return Json(Response { success: false, message: "Username too long, 20 character limit.".to_string() });}
    if password.chars().count() > 255 {return Json(Response { success: false, message: "Password too long, 255 character limit.".to_string() });}

    // Search if account with username or email already exists
    let pool: &MySqlPool = &state.db_pool;
    let res: Option<sqlx::mysql::MySqlRow> = sqlx::query("SELECT username FROM users WHERE username = ? OR email = ?")
        .bind(&username)
        .bind(&email)
        .fetch_optional(pool)
        .await
        .unwrap();

    // Check the result
    if let Some(_) = res {
        return Json(Response { success: false, message: "Account with same username already exists, try again.".to_string() });
    }

    // Branch depending on if email was given, if not given it will be given a default value of NULL
    let password: String = hash(password, DEFAULT_COST).unwrap();
    if email.chars().count() == 0 {
        sqlx::query("INSERT INTO users(username, password) VALUES(?, ?)")
            .bind(&username)
            .bind(&password)
            .execute(pool)
            .await
            .unwrap();
    } else {
        sqlx::query("INSERT INTO users(username, email, password) VALUES(?, ?, ?)")
            .bind(&username)
            .bind(&email)
            .bind(&password)
            .execute(pool)
            .await
            .unwrap();
    }

    println!("User {} has been registered", &username);
    Json(Response { success: true, message: "Signup succesful.".to_string() })
}

async fn handle_login(
    State(state): State<AppState>,
    Json(data): Json<LoginRequest>,
) -> Json<Response> {
    // Get data from request
    let username_or_email: String = data.username_or_email;
    let entered_password: String = data.password;

    // Search if account with username or email exists
    let pool: &MySqlPool = &state.db_pool;
    let res: Option<sqlx::mysql::MySqlRow> = sqlx::query(
        "SELECT password FROM users WHERE username = ? OR email = ?"
    )
    .bind(&username_or_email)
    .bind(&username_or_email)
    .fetch_optional(pool)
    .await
    .unwrap();

    // Get the result from the query
    let mut ok: bool = false;
    if let Some(row) = res {
        let user_password: String = row.get("password");
        if verify(&entered_password, &user_password).unwrap() {ok = true;}
    }

    println!("Got query for {}, returning {}", &username_or_email, &ok);
    match ok {
        false => {
            Json(Response { success: ok, message: "Login failed, username or password is wrong.".to_string() })
        }
        true => {
            Json(Response { success: ok, message: "Login succesful.".to_string() })
        }
    }
}

#[tokio::main]
async fn main() {
    // load environment variables
    dotenv().ok();

    // connect to database
    println!("Connecting to database...");
    let database_url: String = env::var("DATABASE_URL").expect("No DATABASE_URL environment variable found");
    use sqlx::mysql::MySqlPoolOptions;

    // Set up database
    let sql_pool = MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("Couldn't connect");
    let state: AppState = AppState { db_pool: sql_pool };
    println!("Connected to database succesfully, starting service on 127.0.0.1:3000");

    // Set up app and start the service
    let app: Router = Router::new()
        .route("/login", post(handle_login))
        .route("/signup", post(handle_signup))
        .with_state(state);
    
    let listener: TcpListener = TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();

    axum::serve(listener, app).await.unwrap();
}
