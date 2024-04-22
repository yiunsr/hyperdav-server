use env_logger;
use hyperdav_server;
use std::net::SocketAddr;
use std::path::Path;

use tokio::net::TcpListener;
use hyper_util::rt::tokio::TokioIo;
use hyper::server::conn::http1;
use hyper::service::service_fn;


// fn main() {
//     env_logger::init().unwrap();

//     let dav_server = hyperdav_server::Server::new("", Path::new("/"));
//     let server = hyper::server::Server::http("0.0.0.0:8080").unwrap();
//     server
//         .handle()
//         .unwrap();
// }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::env;
    env::set_var("RUST_BACKTRACE", "full");
    env_logger::Builder::new().filter_level(log::LevelFilter::max()).init();

    let addr: SocketAddr = ([127, 0, 0, 1], 9050).into();
    
    let root_dir = r"D:\workspace\vscode3\server_res";
    let dav_server = hyperdav_server::Server::new("http://127.0.0.1:9050", Path::new(root_dir));
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{}", addr);
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let dav_server2 = dav_server.clone();
        tokio::task::spawn(async move {
            let service = service_fn(|req| {
                hyperdav_server::handle(&dav_server2, req)
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await{
                println!("Failed to serve connection: {:?}", err);
            }
    
        });

    }
}