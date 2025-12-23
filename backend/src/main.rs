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

#[derive(Deserialize)]
struct VerifyRequest {
    session_id: String,
}

#[derive(Serialize)]
struct LoginSignupResponse {
    success: bool,
    message: String,
    session_id: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    success: bool,
    username: String,
}

#[derive(Serialize)]
struct LogoutResponse {
    success: bool,
}

fn generate_session_id() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

async fn login(pool: &MySqlPool, user_id: &u64) -> Result<String, Box<dyn Error>> {
    let res: Option<sqlx::mysql::MySqlRow> = sqlx
        ::query("SELECT session_id FROM sessions WHERE user_id = ? AND expires_at > NOW()")
        .bind(user_id)
        .fetch_optional(pool).await?;

    let id: String;
    if let Some(row) = res {
        id = row.get("session_id");
        sqlx
            ::query("UPDATE sessions SET expires_at = ? WHERE session_id = ?")
            .bind(Utc::now() + Duration::days(7))
            .bind(&id)
            .execute(pool).await?;
    } else {
        id = generate_session_id();
        sqlx
            ::query("INSERT INTO sessions(session_id, user_id, expires_at) VALUES(?, ?, ?)")
            .bind(&id)
            .bind(&user_id)
            .bind(Utc::now() + Duration::days(7))
            .execute(pool).await?;
    }

    Ok(id)
}

async fn handle_signup(
    State(state): State<AppState>,
    Json(data): Json<SignupRequest>
) -> Json<LoginSignupResponse> {
    // Get data from the request
    let SignupRequest { username, email, password } = data;
    println!("Got query for {}", &username);

    // Enforce constraints
    if username.is_empty() || password.is_empty() {
        return Json(LoginSignupResponse {
            success: false,
            message: "Username or password fields empty".to_string(),
            session_id: "".to_string(),
        });
    }

    if username.chars().count() > 20 || username.chars().count() < 5 {
        return Json(LoginSignupResponse {
            success: false,
            message: "Username too long or short.".to_string(),
            session_id: "".to_string(),
        });
    }

    if password.chars().count() > 255 || password.chars().count() < 5 {
        return Json(LoginSignupResponse {
            success: false,
            message: "Password too long or short".to_string(),
            session_id: "".to_string(),
        });
    }

    // Search if account with username or email already exists
    let pool: &MySqlPool = &state.db_pool;
    let res: Result<Option<sqlx::mysql::MySqlRow>, sqlx::Error> = sqlx
        ::query("SELECT username FROM users WHERE username = ? OR email = ?")
        .bind(&username)
        .bind(&email)
        .fetch_optional(pool).await;
    match res {
        Ok(result) => {
            match result {
                Some(_) => {
                    return Json(LoginSignupResponse {
                        success: false,
                        message: "Account with same username already exists, try again.".to_string(),
                        session_id: "".to_string(),
                    });
                }
                _ => {}
            }
        }
        Err(err) => {
            eprintln!("Got an error dealing with query in handle_signup, error = {}", err);
            return Json(LoginSignupResponse {
                success: false,
                message: "Internal server error".to_string(),
                session_id: "".to_string(),
            });
        }
    }

    // Branch depending on if email was given, if not given it will be given a default value of NULL
    let password: String = match hash(password, DEFAULT_COST) {
        Ok(hash) => hash,
        Err(err) => {
            eprintln!("Couldn't hash password, error = {}", err);
            return Json(LoginSignupResponse {
                success: false,
                message: "Internal server error".to_string(),
                session_id: "".to_string(),
            });
        }
    };
    if email.is_empty() {
        let res: Result<sqlx::mysql::MySqlQueryResult, sqlx::Error> = sqlx
            ::query("INSERT INTO users(username, password) VALUES(?, ?)")
            .bind(&username)
            .bind(&password)
            .execute(pool).await;
        match res {
            Ok(_) => {}
            Err(err) => {
                eprintln!("Couldn't insert new user, error = {}", err);
                return Json(LoginSignupResponse {
                    success: false,
                    message: "Internal server error".to_string(),
                    session_id: "".to_string(),
                });
            }
        }
    } else {
        let res: Result<sqlx::mysql::MySqlQueryResult, sqlx::Error> = sqlx
            ::query("INSERT INTO users(username, email, password) VALUES(?, ?, ?)")
            .bind(&username)
            .bind(&email)
            .bind(&password)
            .execute(pool).await;
        match res {
            Ok(_) => {}
            Err(err) => {
                eprintln!("Couldn't insert user, error = {}", err);
                return Json(LoginSignupResponse {
                    success: false,
                    message: "Internal server error".to_string(),
                    session_id: "".to_string(),
                });
            }
        }
    }

    // Get the user_id of the newly created account
    println!("User {} has been registered", &username);
    let res: Result<Option<sqlx::mysql::MySqlRow>, sqlx::Error> = sqlx
        ::query("SELECT id FROM users WHERE username = ?")
        .bind(&username)
        .fetch_optional(pool).await;

    let res: Option<sqlx::mysql::MySqlRow> = match res {
        Ok(result) => result,
        Err(err) => {
            eprintln!("Couldn't find user_id of newly created account, error = {}", err);
            return Json(LoginSignupResponse {
                success: false,
                message: "Internal server error".to_string(),
                session_id: "".to_string(),
            });
        }
    };

    // Login the user automatically
    let user_id: u64;
    if let Some(row) = res {
        user_id = row.get("id");
    } else {
        return Json(LoginSignupResponse {
            success: false,
            message: "Internal server error".to_string(),
            session_id: "".to_string(),
        });
    }

    // register a session for the user
    let id: String = match login(pool, &user_id).await {
        Ok(session) => session,
        Err(err) => {
            eprintln!("Error occured while registering session, error = {}", err);
            return Json(LoginSignupResponse {
                success: false,
                message: "Internal server error".to_string(),
                session_id: "".to_string(),
            });
        }
    };

    Json(LoginSignupResponse {
        success: true,
        message: "Signup succesful.".to_string(),
        session_id: id,
    })
}

async fn handle_login(
    State(state): State<AppState>,
    Json(data): Json<LoginRequest>
) -> Json<LoginSignupResponse> {
    // Get data from request
    let LoginRequest { username_or_email, password } = data;

    // Enforce constraints
    if username_or_email.chars().count() < 5 || username_or_email.chars().count() > 20 {
        return Json(LoginSignupResponse {
            success: false,
            message: "Username too short or long".to_string(),
            session_id: "".to_string(),
        });
    }
    if password.chars().count() < 5 || password.chars().count() > 255 {
        return Json(LoginSignupResponse {
            success: false,
            message: "Password too short or long".to_string(),
            session_id: "".to_string(),
        });
    }

    // Search if account with username or email exists
    let pool: &MySqlPool = &state.db_pool;
    let res: Result<Option<sqlx::mysql::MySqlRow>, sqlx::Error> = sqlx
        ::query("SELECT password, id FROM users WHERE username = ? OR email = ?")
        .bind(&username_or_email)
        .bind(&username_or_email)
        .fetch_optional(pool).await;

    let res: Option<sqlx::mysql::MySqlRow> = match res {
        Ok(result) => result,
        Err(err) => {
            eprintln!("Couldn't get password and id from username or email in handle_login, {}", err);
            return Json(LoginSignupResponse {
                success: false,
                message: "Internal server error".to_string(),
                session_id: "".to_string(),
            });
        }
    };

    // Get the result from the query
    let user_id: u64;
    if let Some(row) = res {
        let user_password: String = row.get("password");
        let ok: bool = match verify(&password, &user_password) {
            Ok(val) => val,
            Err(err) => {
                eprintln!("Couldn't validate password, error = {}", err);
                return Json(LoginSignupResponse {
                    success: false,
                    message: "Internal server error".to_string(),
                    session_id: "".to_string(),
                });
            }
        };
        if ok {
            user_id = row.get("id");
        } else {
            return Json(LoginSignupResponse {
                success: false,
                message: "Username or password incorrect".to_string(),
                session_id: "".to_string(),
            });
        }
    } else {
        return Json(LoginSignupResponse {
            success: false,
            message: "Username or password incorrect".to_string(),
            session_id: "".to_string(),
        });
    }

    let id: String = match login(pool, &user_id).await {
        Ok(session) => session,
        Err(err) => {
            eprintln!("Error in setting session, error = {}", err);
            return Json(LoginSignupResponse {
                success: false,
                message: "Internal server error".to_string(),
                session_id: "".to_string(),
            });
        }
    };

    Json(LoginSignupResponse {
        success: true,
        message: "Login success".to_string(),
        session_id: id,
    })
}

async fn handle_verify(
    State(state): State<AppState>,
    Json(data): Json<VerifyRequest>
) -> Json<VerifyResponse> {
    // Get pool and session_id from parameters
    let pool: &MySqlPool = &state.db_pool;
    let session_id: String = data.session_id;

    if session_id.is_empty() {
        return Json(VerifyResponse { success: false, username: "".to_string() });
    }

    // Run query to validate session
    let res: Result<Option<sqlx::mysql::MySqlRow>, sqlx::Error> = sqlx
        ::query("SELECT user_id FROM sessions WHERE session_id = ? AND expires_at > NOW()")
        .bind(session_id)
        .fetch_optional(pool).await;

    let res: Option<sqlx::mysql::MySqlRow> = match res {
        Ok(val) => val,
        Err(err) => {
            eprintln!("Couldn't get user_id from session_id given, error = {}", err);
            return Json(VerifyResponse { success: false, username: "".to_string() });
        }
    };

    let user_id: u64;
    if let Some(row) = res {
        user_id = row.get("user_id");
    } else {
        return Json(VerifyResponse { success: false, username: "".to_string() });
    }

    // run query to validate user_id
    let res: Result<Option<sqlx::mysql::MySqlRow>, sqlx::Error> = sqlx
        ::query("SELECT username FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool).await;

    let res: Option<sqlx::mysql::MySqlRow> = match res {
        Ok(val) => val,
        Err(err) => {
            eprintln!("Couldn't get username from user_id got, error = {}", err);
            return Json(VerifyResponse { success: false, username: "".to_string() });
        }
    };

    let username: String;
    if let Some(row) = res {
        username = row.get("username");
    } else {
        return Json(VerifyResponse { success: false, username: "".to_string() });
    }

    Json(VerifyResponse { success: true, username: username })
}

async fn handle_logout(
    State(state): State<AppState>,
    Json(data): Json<VerifyRequest>
) -> Json<LogoutResponse> {
    let pool: &MySqlPool = &state.db_pool;
    let session_id = data.session_id;
    if session_id.is_empty() {
        return Json(LogoutResponse { success: false });
    }

    let res: Result<Option<sqlx::mysql::MySqlRow>, sqlx::Error> = sqlx
        ::query("SELECT user_id FROM sessions WHERE session_id = ?")
        .bind(&session_id)
        .fetch_optional(pool).await;

    let res: Option<sqlx::mysql::MySqlRow> = match res {
        Ok(val) => val,
        Err(err) => {
            eprintln!("Database error in handle_logout, error = {}", err);
            return Json(LogoutResponse { success: false });
        }
    };

    if let None = res {
        return Json(LogoutResponse { success: false });
    }

    let res = sqlx
        ::query("DELETE FROM sessions WHERE session_id = ?")
        .bind(&session_id)
        .execute(pool).await;

    match res {
        Ok(_) => {}
        Err(err) => {
            eprintln!("Got error deleting session, error = {}", err);
            return Json(LogoutResponse { success: false });
        }
    }

    Json(LogoutResponse { success: true })
}

#[tokio::main]
async fn main() {
    // load environment variables
    dotenv().ok();

    // connect to database
    println!("Connecting to database...");
    let database_url: String = env
        ::var("DATABASE_URL")
        .expect("No DATABASE_URL environment variable found");
    use sqlx::mysql::MySqlPoolOptions;

    // Set up database
    let sql_pool = MySqlPoolOptions::new().connect(&database_url).await.expect("Couldn't connect");
    let state: AppState = AppState { db_pool: sql_pool };
    println!("Connected to database succesfully, starting service on 127.0.0.1:3000");

    // Set up app and start the service
    let app: Router = Router::new()
        .route("/login", post(handle_login))
        .route("/signup", post(handle_signup))
        .route("/verify", post(handle_verify))
        .route("/logout", post(handle_logout))
        .with_state(state);

    let listener: TcpListener = TcpListener::bind("127.0.0.1:3000").await.unwrap();

    axum::serve(listener, app).await.unwrap();
}
