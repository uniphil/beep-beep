// use hyper::server::conn::Parts;
use hyper::Uri;
use std::convert::Infallible;
use std::net::SocketAddr;

use hyper::{Body, Method, Request, Response, Server, StatusCode};
use hyper::http;
use hyper::service::{make_service_fn, service_fn};

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

fn visitor(req: Request<Body>) -> Option<(Option<[u8; 8]>, String, String)> {
    let headers = req.headers();
    let dnt = headers.get("dnt").map_or(false, |v| v == "1");
    let identifier = if false && dnt { None } else {
        let ip = headers.get("x-forwarded-for");
        let ua = headers.get("user-agent");
        println!("{:?} {:?}", ip, ua);
        Some(*b"xxxxxxxx")
    };
    let referer = headers.get("referer");
    if let Some(raw) = referer {
        let uri = raw.to_str().unwrap().parse::<Uri>();
        println!("uri {:?}", uri);
        println!("host {:?}", (&uri).clone().as_ref().unwrap().host());
        println!("path {:?}", uri.unwrap().path());
    }
    println!("ref {:?}", referer);
    Some((identifier, "host".to_string(), "path".to_string()))
}

async fn handle(req: Request<Body>) -> http::Result<Response<Body>> {
    if req.method() == &Method::GET {
        let p = req.uri().path();
        if p.is_ascii() && p.starts_with("/") && p.ends_with(".gif") && p.len() == (1 + 16 + 4) {
            let _key = &p[1..17];
            let _v = visitor(req);
            return Response::builder()
                .header("Content-Type", "image/gif")
                .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                .header("Pragma", "no-cache")
                .body(Body::from(HELLO_PIXEL))            
        }
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
