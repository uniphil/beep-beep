use std::collections::hash_map::DefaultHasher;
use std::convert::{Infallible, TryInto, TryFrom};
use std::error::Error;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::ops::Deref;
use std::time::Instant;
use chrono::{Datelike, Local};
use hyper::{Body, Method, Request, Response, Server, StatusCode, Uri, http};
use hyper::service::{make_service_fn, service_fn};
use redis::{AsyncCommands, RedisError};

static HELLO_PIXEL: &[u8] = &[
    // 💜                                                                       //R     G     B
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x01, 0x00, 0xc4, 0x52, 0xc8,
    0xff, 0xff, 0xff, 0x21, 0xfe, 0x02, 0x3c, 0x33, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
];

static BAD_PIXEL: &[u8] = &[
    // 🖤
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0x21, 0xfe, 0x02, 0x3c, 0x33, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
];

#[derive(Debug, Clone, Copy)]
struct Key([u8; 16]);
impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Key({})", String::from_utf8(self.0.to_vec()).expect("[invalid key bytes]"))
    }
}
impl TryFrom<&[u8]> for Key {
    type Error = std::array::TryFromSliceError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        value.try_into().map(|arr: &[u8; 16]| Key(*arr))
    }
}
impl Deref for Key {
    type Target = [u8; 16];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
enum BeepBeepError<'a> {
    Redis(RedisError),
    KeyNotFound(Key),
    WrongDomain((Key, &'a str)),
}

impl<'a> BeepBeepError<'a> {
    fn key_not_found(key: Key) -> Self {
        BeepBeepError::KeyNotFound(key)
    }
    fn wrong_domain(key: Key, tried_domain: &'a str) -> Self {
        BeepBeepError::WrongDomain((key, tried_domain))
    }
}
impl<'a> fmt::Display for BeepBeepError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &*self {
            BeepBeepError::Redis(ref err) => err.fmt(f),
            BeepBeepError::KeyNotFound(key) => write!(f, "Key not found: '{}'", key),
            BeepBeepError::WrongDomain((key, ref domain)) => write!(f, "Domain '{}' can't be counted for key '{}'", domain, key),
        }
    }
}
impl<'a> Error for BeepBeepError<'a> {}
impl<'a> From<RedisError> for BeepBeepError<'a> {
    fn from(err: RedisError) -> BeepBeepError<'a> {
        BeepBeepError::Redis(err)
    }
}

fn visitor(req: &Request<Body>) -> Option<(Key, Option<u64>, String, String)> {
    if req.method() != &Method::GET {
        return None
    };
    let key: Key = match req.uri().path().as_bytes() {
        [b'/', k @ .., b'.', b'g', b'i', b'f'] =>
            if let (true, Ok(k_)) = (k.is_ascii(), k.try_into()) {
                k_ } else { return None }
        _ => { return None }
    };
    let headers = req.headers();
    let dnt = headers.get("dnt").map_or(false, |v| v == "1");
    let identifier = if false && dnt { None } else {
        let ip = headers.get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_else(|| {
                eprintln!("missing x-forwarded-for");
                "127.0.0.1"  // handle better in production
            });
        let ua = match headers.get("user-agent").and_then(|v| v.to_str().ok()) {
            Some(v) => v,
            None => { return None },  // prob not a browser visit
        };
        let mut hasher = DefaultHasher::new();
        Hash::hash_slice(&[ip, ua], &mut hasher);
        Some(hasher.finish())
    };
    let (host, path) = match headers.get("referer")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<Uri>().ok()) {
        Some(uri) =>
            if let Some(host) = uri.host() {
                (host.to_string(), uri.path().to_string())
            } else { return None },  // we need to know the host!
        None => { return None },  // no referrer: can't know what to do with this req
    };
    Some((key, identifier, host, path))
}

async fn count<'a>(key: Key, identifier: Option<u64>, host: &'a str, path: &'a str) -> Result<(), BeepBeepError<'a>> {
    let date_ord = {
        let today = Local::today();
        today.year() as f32 + today.ordinal() as f32 / 1000.
    };
    let client = redis::Client::open("redis://127.0.0.1:6379")?;
    let mut con = client.get_async_connection().await?;
    let domain = con.get::<_, Option<String>>(format!("domains:{}", key)).await?
        .ok_or(BeepBeepError::key_not_found(key))?;
    if &domain != host {
        return Err(BeepBeepError::wrong_domain(key, host))
    }

    if let Some(id) = identifier {
        let hll_key = &format!("counts:hll:{}:{}:{}", host, date_ord, path);
        let abs_key = &format!("counts:abs:{}:{}:{}", host, date_ord, path);
        redis::pipe()
            .pfadd(hll_key, id).ignore()
            .incr(abs_key, 1u8).ignore()
            .zadd(format!("counts:hlls:all:{}", host), hll_key, date_ord).ignore()
            .zadd(format!("counts:hlls:path:{}/{}", host, path), hll_key, date_ord).ignore()
            .zadd(format!("counts:abss:all:{}", host), abs_key, date_ord).ignore()
            .zadd(format!("counts:abss:path:{}/{}", host, path), abs_key, date_ord).ignore()
            .query_async(&mut con).await?;
    } else {
        let dnt_key = &format!("counts:abs:{}:{}", host, date_ord);
        redis::pipe()
            .incr(dnt_key, 1u8).ignore()
            .zadd(format!("counts:dnt:{}", host), dnt_key, date_ord).ignore()
            .query_async(&mut con).await?;
    }
    Ok(())
}

async fn handle(req: Request<Body>) -> http::Result<Response<Body>> {
    let t0 = Instant::now();
    let rv = handle_inner(req).await;
    println!("{}us {:?}", t0.elapsed().as_micros(), match rv {
        Ok(ref r) => format!("{}", r.status()),
        Err(ref e) => format!("err: {}", e),
    });
    rv
}
async fn handle_inner(req: Request<Body>) -> http::Result<Response<Body>> {
    if let Some((key, identifier, host, path)) = visitor(&req) {
        match count(key, identifier, &host, &path).await {
            Ok(_) => {
                return Response::builder()
                    .header("Content-Type", "image/gif")
                    .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                    .header("Pragma", "no-cache")
                    .body(Body::from(HELLO_PIXEL))
            },
            Err(e) => {
                eprintln!("error counting: {}", e);
            }
        };
    }
    Response::builder()
        .header("Content-Type", "image/gif")
        .status(StatusCode::BAD_REQUEST)
        .body(Body::from(BAD_PIXEL))
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
}

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let make_service = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(handle))
    });
    let server = Server::bind(&addr).serve(make_service);
    let graceful = server.with_graceful_shutdown(shutdown_signal());
    if let Err(e) = graceful.await {
        eprintln!("server error: {}", e);
    }
    println!("\nbye!");
}
