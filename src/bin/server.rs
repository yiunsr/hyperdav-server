use env_logger;
use hyperdav_server;
use warp::Filter;
use std::net::SocketAddr;
use std::path::Path;
use std::io::Write;

use tokio::net::TcpListener;

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
    env_logger::Builder::new()
        .format(|buf, record| {
            writeln!(
                buf, "{}:{} {} [{}] - {}",
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .filter_level(log::LevelFilter::max()).init();

    let addr: SocketAddr = ([127, 0, 0, 1], 9050).into();
    
    let root_dir = r"D:\workspace\vscode3\server_res";
    let dav_server = hyperdav_server::Server::new("http://127.0.0.1:9050", Path::new(root_dir));
    let route = hyperdav_server::handle(&dav_server).await;
    let routes = hyperdav_server::index_filter().or(
        route
    );
    warp::serve(routes).run(addr).await;
    return Ok(());
}