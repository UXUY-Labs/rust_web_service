use std::{convert::Infallible, io};

use actix_files::{Files, NamedFile};
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{
    error, get,
    http::{
        header::{self, ContentType},
        Method, StatusCode,
    },
    middleware, web, App, Either, HttpRequest, HttpResponse, HttpServer, Responder, Result,
};
use ethers::prelude::Http;
use async_stream::stream;
use serde::{Deserialize, Serialize};
use serde_json::json;

// NOTE: Not a suitable session key for production.
static SESSION_SIGNING_KEY: &[u8] = &[0; 64];

/// favicon handler
#[get("/favicon")]
async fn favicon() -> Result<impl Responder> {
    Ok(NamedFile::open("static/favicon.ico")?)
}

/// simple index handler
#[get("/welcome")]
async fn welcome(req: HttpRequest, session: Session) -> Result<HttpResponse> {
    println!("{req:?}");

    // session
    let mut counter = 1;
    if let Some(count) = session.get::<i32>("counter")? {
        println!("SESSION value: {count}");
        counter = count + 1;
    }

    // set counter to session
    session.insert("counter", counter)?;

    // response
    Ok(HttpResponse::build(StatusCode::OK)
        .content_type(ContentType::plaintext())
        .body(include_str!("../static/welcome.html")))
}

async fn default_handler(req_method: Method) -> Result<impl Responder> {
    match req_method {
        Method::GET => {
            let file = NamedFile::open("static/404.html")?
                .customize()
                .with_status(StatusCode::NOT_FOUND);
            Ok(Either::Left(file))
        }
        _ => Ok(Either::Right(HttpResponse::MethodNotAllowed().finish())),
    }
}

/// response body
async fn response_body(path: web::Path<String>) -> HttpResponse {
    let name = path.into_inner();

    HttpResponse::Ok()
        .content_type(ContentType::plaintext())
        .streaming(stream! {
            yield Ok::<_, Infallible>(web::Bytes::from("Hello "));
            yield Ok::<_, Infallible>(web::Bytes::from(name));
            yield Ok::<_, Infallible>(web::Bytes::from("!"));
        })
}


#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct IndexResponse {
    user_id: String,
    counter: i32,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct LnUrlMeta {
    #[serde(rename = "text/identifier")]
    pub text_identifier: String,
    #[serde(rename = "text/plain")]
    pub text_plain: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct LnUrlStruct {
    pub callback: String,
    #[serde(rename = "maxSendable")]
    pub max_sendable: i64,
    #[serde(rename = "minSendable")]
    pub min_sendable: i64,
    pub metadata: String,
    #[serde(rename = "commentAllowed")]
    pub comment_allowed: i64,
    pub tag: String,
    #[serde(rename = "allowsNostr")]
    pub allows_nostr: bool,
    #[serde(rename = "nostrPubkey")]
    pub nostr_pubkey: String,
}


#[derive(Serialize, Deserialize)]
struct PayReq {
    pub pr: String,
    pub routes: Vec<String>,
}

async fn generate_invoice(req: HttpRequest, path: web::Path<(String,)>) -> HttpResponse {
    println!("{req:?}");

    let resp = PayReq{ pr: "lnbc100n1pj5w7jfpp5x2w7wj83ue3ze6mwffg7q9pkhfaq8drcn886anu7204cz9cexycqdq8w4u827gcqzzsxqyz5vqsp53zq5euxg2yhanqdgn0x2wh2w5wrv75epdz0e7835ex5n475qpcks9qyyssqfdagsz4esqmjjd3ruqc4tt786azn0c8xlfqjx57vndgm03huyhkzecctk00sctxqdfx83qdjsme9ax25qadqd6py9hpzelvjwfxtemcqw60uqa".to_string(), routes: Vec::from(["".to_string()]) };
    HttpResponse::Ok()
        .content_type(ContentType::json())
        .json(resp)
}

async fn with_param(req: HttpRequest, path: web::Path<(String,)>) -> HttpResponse {
    println!("{req:?}");
    let resp = LnUrlStruct{
        callback: "https://uxuy.one/lnd/payreq/1000".to_string(),
        max_sendable: 100000000,
        min_sendable: 1000,
        metadata: "[[\"text/plain\",\"Pay to Wallet of Satoshi user: kevin\"],[\"text/identifier\",\"kevin@walletofsatoshi.com\"]]".to_string(),
        comment_allowed: 255,
        tag: "payRequest".to_string(),
        allows_nostr: false,
        nostr_pubkey: "".to_string(),
    };

    HttpResponse::Ok()
        .content_type(ContentType::json())
        .json(resp)

    // HttpResponse::Ok()
    //     .content_type(ContentType::plaintext())
    //     .body(format!("Hello {}!", path.0))
}



#[actix_web::main]
async fn main() -> io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // random key means that restarting server will invalidate existing session cookies
    let key = actix_web::cookie::Key::from(SESSION_SIGNING_KEY);

    log::info!("starting HTTP server at http://0.0.0.0:9000");

    HttpServer::new(move || {
        App::new()
            // enable automatic response compression - usually register this first
            .wrap(middleware::Compress::default())
            // cookie session middleware
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), key.clone())
                    .cookie_secure(false)
                    .build(),
            )
            // enable logger - always register Actix Web Logger middleware last
            .wrap(middleware::Logger::default())
            // register favicon
            .service(favicon)
            // register simple route, handle all methods
            .service(welcome)
            // with path parameters
            .service(web::resource("/.well-known/lnurlp/{name}").route(web::get().to(with_param)))
            .service(web::resource("/lnd/payreq/{amt}").route(web::get().to(generate_invoice)))
            // async response body
            .service(web::resource("/async-body/{name}").route(web::get().to(response_body)))
            .service(
                web::resource("/test").to(|req: HttpRequest| match *req.method() {
                    Method::GET => HttpResponse::Ok(),
                    Method::POST => HttpResponse::MethodNotAllowed(),
                    _ => HttpResponse::NotFound(),
                }),
            )
            .service(web::resource("/error").to(|| async {
                error::InternalError::new(
                    io::Error::new(io::ErrorKind::Other, "test"),
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            }))
            // static files
            .service(Files::new("/static", "static").show_files_listing())
            // redirect
            .service(
                web::resource("/").route(web::get().to(|req: HttpRequest| async move {
                    println!("{req:?}");
                    HttpResponse::Found()
                        .insert_header((header::LOCATION, "static/welcome.html"))
                        .finish()
                })),
            )
            // default
            .default_service(web::to(default_handler))
    })
        .bind(("0.0.0.0", 9000))?
        .workers(2)
        .run()
        .await
}