//! WebDAV server as a hyper server handler
//!
//!```no_run
//!extern crate hyper;
//!extern crate hyperdav_server;
//!
//!let server = hyper::server::Server::http("0.0.0.0:8080").unwrap();
//!server
//!    .handle(hyperdav_server::Server::new("", std::path::Path::new("/")))
//!    .unwrap();
//!```
//! 

use futures;
use bytes::{Bytes, Buf};
use url::Url;

use std::convert::Infallible;
use std::borrow::{Borrow, Cow};
use std::str::FromStr;
use std::time::{UNIX_EPOCH, SystemTime};
use std::io::{self, Read, Write, ErrorKind};
use std::fs::{Metadata, read_dir, File};
use std::path::{Path, PathBuf};
use log::{error, debug};

use warp::hyper::StatusCode;
use warp::{hyper::Method, reject, Filter, Rejection, Reply, filters::BoxedFilter};
use warp::http::Response;

#[derive(Debug)]
struct MethodError;
impl reject::Reject for MethodError {}


use percent_encoding::percent_decode;
use mime_guess;

use xml::reader::ParserConfig;
use xml::writer::EmitterConfig;
use xml::common::XmlVersion;
use xml::name::{Name, OwnedName};
use xml::reader::XmlEvent;
use xml::writer::EventWriter;
use xml::writer::XmlEvent as XmlWEvent;


static INTERNAL_SERVER_ERROR: &[u8] = b"Internal Server Error";
static NOTFOUND: &[u8] = b"Not Found";
static BAD_REQUEST: &[u8] = b"bad Request";

#[derive(Debug, Clone)]
struct ServerPath {
    // HTTP path on the server representing the root directory
    pub url_prefix: Cow<'static, str>,
    // Root file system directory of the server
    pub srv_root: Cow<'static, Path>,
}


impl ServerPath {
    // Ex. url_prefix = "/dav", srv_root = "/srv/dav/"
    fn new<U, R>(url_prefix: U, srv_root: R) -> Self
        where U: Into<Cow<'static, str>>, R: Into<Cow<'static, Path>> {
        let url_prefix = url_prefix.into();
        let srv_root = srv_root.into();

        // assert_eq!(url_prefix.trim_right_matches("/"), url_prefix);
        // assert!(srv_root.ends_with("/"));

        ServerPath {url_prefix, srv_root}
    }

    fn file_to_url<P: AsRef<Path>>(&self, path: P) -> String {
        let mut path = path.as_ref().to_string_lossy().to_string();
        if path.starts_with(self.srv_root.to_str().unwrap()){
            path = path.replace(self.srv_root.to_str().unwrap(), "");
        }
        
        
        // space to "%20" encoding
        // 최소한의 url encoding만 해준다.
        let path = path.replace(" ", "%20");
        let url = self.url_prefix.clone().into_owned() + &path;

        return url;
        // url.bytes().map(percent_encode_byte).collect::<String>()
    }

    fn url_to_file<'a>(&'a self, url: &'a str) -> Option<PathBuf> {
        debug!("url_to_file url : {}", url);
        if url.starts_with(self.url_prefix.borrow() as &str) {
            let subpath = &url[self.url_prefix.len()..]
                               .trim_start_matches("/")
                               .trim_end_matches("/");
            let mut ret = self.srv_root.clone().into_owned();
            ret.push(subpath);
            Some(ret)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct Server {
    serverpath: ServerPath,
}

impl Server {
    /// Create a WebDAV handler
    ///
    /// * `url_prefix` - the path on the server that maps to the WebDAV root. It
    /// must not end with trailing slashes.
    ///
    /// * `srv_root` - must be a directory on the host and must end with a trailing slash.
    ///
    /// Panics if the above requirements are not met.
    /// These requirements are desired to consistently map between server URLs
    /// and host file system paths. Since the server returns URLs for files,
    /// the mapping must be consistent in both directions.
    ///
    /// Ex. url_prefix = "/dav", srv_root = Path::new("/srv/dav/")
    pub fn new<U, R>(url_prefix: U, srv_root: R) -> Self
        where U: Into<Cow<'static, str>>, R: Into<Cow<'static, Path>> {
        Server { serverpath: ServerPath::new(url_prefix, srv_root) }
    }
}

#[derive(Debug)]
enum RequestType {
    Options,
    Propfind,
    Get,
    Copy,
    Move,
    Delete,
    Put,
    Mkdir,
}

#[derive(Debug)]
enum Error {
    ParseError,
    BadPath,
    XmlReader(xml::reader::Error),
    XmlWriter(xml::writer::Error),
    Io(io::Error),
}

impl From<xml::reader::Error> for Error {
    fn from(e: xml::reader::Error) -> Self {
        Error::XmlReader(e)
    }
}

impl From<xml::writer::Error> for Error {
    fn from(e: xml::writer::Error) -> Self {
        Error::XmlWriter(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

fn parse_propfind<R: Read, F: FnMut(OwnedName) -> ()>(mut xml: xml::reader::EventReader<R>,
                                                      mut f: F)
                                                      -> Result<(), Error> {
    enum State {
        Start,
        PropFind,
        Prop,
        InProp,
    }

    let mut state = State::Start;

    loop {
        let event = xml.next()?;
        match state {
            State::Start => {
                match event {
                    XmlEvent::StartDocument { .. } => (),
                    XmlEvent::StartElement { ref name, .. } if name.local_name == "propfind" => {
                        state = State::PropFind;
                    }
                    _ => return Err(Error::ParseError),
                }
            }
            State::PropFind => {
                match event {
                    XmlEvent::StartElement { ref name, .. } if name.local_name == "prop" => {
                        state = State::Prop;
                    }
                    _ => return Err(Error::ParseError),
                }
            }
            State::Prop => {
                match event {
                    XmlEvent::StartElement { name, .. } => {
                        state = State::InProp;
                        f(name);
                    }
                    XmlEvent::EndElement { .. } => {
                        return Ok(());
                    }
                    _ => return Err(Error::ParseError),
                }
            }
            State::InProp => {
                match event {
                    XmlEvent::EndElement { .. } => {
                        state = State::Prop;
                    }
                    _ => return Err(Error::ParseError),
                }
            }
        }
    }
}

fn write_client_prop<W: Write>(xmlwriter: &mut EventWriter<W>,
                               prop: Name)
                               -> Result<(), xml::writer::Error> {
    if let Some(namespace) = prop.namespace {
        if let Some(prefix) = prop.prefix {
            // Remap the client's prefix if it overlaps with our DAV: prefix
            if prefix == "D" && namespace != "DAV:" {
                let newname = Name {
                    local_name: prop.local_name,
                    namespace: Some(namespace),
                    prefix: Some("U"),
                };
                return xmlwriter.write(XmlWEvent::start_element(newname).ns("U", namespace));
            }
        }
    }
    xmlwriter.write(XmlWEvent::start_element(prop))
}

fn systime_to_format(time: SystemTime) -> String {
    use chrono::DateTime;
    use chrono::Utc;

    let unix = time.duration_since(UNIX_EPOCH).unwrap();
    let time: DateTime<Utc> = DateTime::from_timestamp(unix.as_secs() as i64, unix.subsec_nanos()).unwrap();
    time.to_rfc3339_opts(chrono::format::SecondsFormat::Secs, true)
}

fn handle_prop_path<W: Write>(xmlwriter: &mut EventWriter<W>, path: &PathBuf, url: &str,
            meta: &Metadata, prop: Name) -> Result<bool, Error> {
    match (prop.namespace, prop.local_name) {
        (Some("DAV:"), "resourcetype") => {
            xmlwriter.write(XmlWEvent::start_element("D:resourcetype"))?;
            if meta.is_dir() {
                xmlwriter.write(XmlWEvent::start_element("D:collection"))?;
                xmlwriter.write(XmlWEvent::end_element())?;
            }
            xmlwriter.write(XmlWEvent::end_element())?;
            Ok(true)
        }
        (Some("DAV:"), "creationdate") => {
            if let Ok(time) = meta.created() {
                xmlwriter.write(XmlWEvent::start_element("D:creationdate"))?;
                xmlwriter
                    .write(XmlWEvent::characters(&systime_to_format(time)))?;
                xmlwriter.write(XmlWEvent::end_element())?;
                Ok(true)
            } else {
                Ok(false)
            }
        }
        (Some("DAV:"), "getlastmodified") => {
            if let Ok(time) = meta.modified() {
                xmlwriter
                    .write(XmlWEvent::start_element("D:getlastmodified"))?;
                xmlwriter
                    .write(XmlWEvent::characters(&systime_to_format(time)))?;
                xmlwriter.write(XmlWEvent::end_element())?;
                Ok(true)
            } else {
                Ok(false)
            }
        }
        (Some("DAV:"), "getcontentlength") => {
            xmlwriter
                .write(XmlWEvent::start_element("D:getcontentlength"))?;
            xmlwriter
                .write(XmlWEvent::characters(&meta.len().to_string()))?;
            xmlwriter.write(XmlWEvent::end_element())?;
            Ok(true)
        }
        (Some("DAV:"), "getcontenttype") => {
            xmlwriter
                .write(XmlWEvent::start_element("D:getcontenttype"))?;
            if meta.is_dir() {
                xmlwriter
                    .write(XmlWEvent::characters("httpd/unix-directory"))?;
            } else {
                xmlwriter.write(XmlWEvent::characters("text/plain"))?;
            }
            xmlwriter.write(XmlWEvent::end_element())?;
            Ok(true)
        }
        (Some("DAV:"), "displayname") => {
            let file_name = path.file_name().unwrap().to_string_lossy().to_string();
            xmlwriter
                .write(XmlWEvent::start_element("D:displayname"))?;
            xmlwriter
                .write(XmlWEvent::characters(&file_name))?;
            xmlwriter.write(XmlWEvent::end_element())?;
            Ok(true)
        }
        (Some("DAV:"), "getetag") => {
            let etag = get_etag(&meta);
            xmlwriter
                .write(XmlWEvent::start_element("D:getetag"))?;
            xmlwriter
                .write(XmlWEvent::characters(&etag))?;
            xmlwriter.write(XmlWEvent::end_element())?;
            Ok(true)
        }
        (Some("DAV:"), "lockdiscovery") => {
            xmlwriter
                .write(XmlWEvent::start_element("D:lockdiscovery"))?;
            xmlwriter.write(XmlWEvent::end_element())?;
            Ok(true)
        }
        (Some("DAV:"), "supportedlock") => {
            xmlwriter
                .write(XmlWEvent::start_element("D:supportedlock"))?;
            xmlwriter.write(XmlWEvent::end_element())?;
            Ok(true)
        }
        
        _ => Ok(false),
    }
}

fn get_etag(meta: &Metadata)->String{
    let modified = meta.modified().unwrap();
    let t = modified.duration_since(UNIX_EPOCH).ok().unwrap();
    let t = t.as_secs() * 1000000 + t.subsec_nanos() as u64 / 1000;
    if meta.is_file() {
        format!("{:x}", t)
    } else {
        format!("{:x}", t)
    }
}

fn handle_propfind_path<W: Write>(xmlwriter: &mut EventWriter<W>, path: &PathBuf, url: &str,
            meta: &Metadata, props: &[OwnedName])-> Result<(), Error> {
    xmlwriter.write(XmlWEvent::start_element("D:response"))?;

    debug!("handle_propfind_path path: {:?}", path);

    let path_result = Url::parse(url);
    if path_result.is_err() {
        let err = path_result.err().unwrap();
        error!("err : {}", err);
        return Ok(());
    }
    let pathname = path_result.unwrap();
    // .unwrap();
    let pathname = pathname.path();
    debug!("pathname : {}", pathname);
    xmlwriter.write(XmlWEvent::start_element("D:href"))?;
    xmlwriter.write(XmlWEvent::characters(pathname))?;
    xmlwriter.write(XmlWEvent::end_element())?; // href

    let mut failed_props = Vec::with_capacity(props.len());
    xmlwriter.write(XmlWEvent::start_element("D:propstat"))?;
    xmlwriter.write(XmlWEvent::start_element("D:prop"))?;
    for prop in props {
        if !handle_prop_path(xmlwriter, path, url, meta, prop.borrow())? {
            failed_props.push(prop);
        }
    }
    xmlwriter.write(XmlWEvent::end_element())?; // prop
    xmlwriter.write(XmlWEvent::start_element("D:status"))?;
    if failed_props.len() >= props.len() {
        // If they all failed, make this a failure response and return
        xmlwriter
            .write(XmlWEvent::characters("HTTP/1.1 404 Not Found"))?;
        xmlwriter.write(XmlWEvent::end_element())?; // status
        xmlwriter.write(XmlWEvent::end_element())?; // propstat
        xmlwriter.write(XmlWEvent::end_element())?; // response
        return Ok(());
    }
    xmlwriter.write(XmlWEvent::characters("HTTP/1.1 200 OK"))?;
    xmlwriter.write(XmlWEvent::end_element())?; // status
    xmlwriter.write(XmlWEvent::end_element())?; // propstat
    xmlwriter.write(XmlWEvent::end_element())?; // response

    return Ok(());

    // Handle the failed properties
    xmlwriter.write(XmlWEvent::start_element("D:propstat"))?;
    xmlwriter.write(XmlWEvent::start_element("D:prop"))?;
    for prop in failed_props {
        write_client_prop(xmlwriter, prop.borrow())?;
        xmlwriter.write(XmlWEvent::end_element())?;
    }
    xmlwriter.write(XmlWEvent::end_element())?; // prop
    xmlwriter.write(XmlWEvent::start_element("D:status"))?;
    xmlwriter
        .write(XmlWEvent::characters("HTTP/1.1 404 Not Found"))?;
    xmlwriter.write(XmlWEvent::end_element())?; // status
    xmlwriter.write(XmlWEvent::end_element())?; // propstat
    xmlwriter.write(XmlWEvent::end_element())?; // response
    Ok(())
}

fn route_method_option() -> BoxedFilter<(impl Reply,)>{
    let option_route = method("OPTIONS")
    //.and(warp::path!(""))
    .map(warp::reply)
    .map(|reply| {
            warp::reply::with_header(reply, "Access-Control-Allow-Methods", "OPTIONS,GET,PUT,DELETE,PROPFIND,COPY,MOVE")
    })
    .recover(handle_not_found).boxed();
    return option_route;
}

fn route_method_propfind(server:&Server) -> BoxedFilter<(impl Reply,)>{
    let server2 = server.clone();
    let option_route = method("PROPFIND")
        //.and(warp::path!(""))
        .and(warp::path::full())
        .and(warp::header("Depth"))
        .and(warp::body::bytes())
        .map(move |fullpath: warp::path::FullPath, depth: u32, full_body:bytes::Bytes| {
            server2.handle_propfind(fullpath, depth, full_body)
        })
        .recover(handle_not_found).boxed();
    return option_route;
}

// fn io_error_to_status(e: io::Error) -> Response<BoxBody<Bytes, std::io::Error>>{
//     if e.kind() == ErrorKind::NotFound {
//         let res = Response::builder()
//                 .status(StatusCode::NOT_FOUND)
//                 .body(Full::new(NOTFOUND.into()).map_err(|e| match e {}).boxed())
//                 .unwrap();
//         return res;
//     }

//     let res = Response::builder()
//                 .status(StatusCode::INTERNAL_SERVER_ERROR)
//                 .body(Full::new(INTERNAL_SERVER_ERROR.into()).map_err(|e| match e {}).boxed())
//                 .unwrap();
//     return res;
// }

// fn make_error_res(status_code:StatusCode)-> Response<BoxBody<Bytes, std::io::Error>>{
//     let res_builder = Response::builder()
//         .status(status_code);
//     let res_builder = match status_code{
//         StatusCode::INTERNAL_SERVER_ERROR => res_builder.body(Full::new(INTERNAL_SERVER_ERROR.into()).map_err(|e| match e {}).boxed()),
//         StatusCode::NOT_FOUND => res_builder.body(Full::new(NOTFOUND.into()).map_err(|e| match e {}).boxed()),
//         StatusCode::BAD_REQUEST => res_builder.body(Full::new(BAD_REQUEST.into()).map_err(|e| match e {}).boxed()),
//         _ => res_builder.body(Full::new(INTERNAL_SERVER_ERROR.into()).map_err(|e| match e {}).boxed()),
//     };
//     return res_builder.unwrap();
// }


impl Server {
    fn handle_propfind_path_recursive<W: Write>(&self,
                                                path: &Path,
                                                depth: u32,
                                                xmlwriter: &mut EventWriter<W>,
                                                props: &[OwnedName])
                                                -> Result<(), Error> {
        if depth == 0 {
            return Ok(());
        }
        for f in read_dir(path)? {
            let f = match f {
                Ok(f) => f,
                Err(e) => {
                    error!("Read dir error. Skipping {:?}", e);
                    continue;
                }
            };
            let path = f.path();
            let meta = match f.metadata() {
                Ok(meta) => meta,
                Err(e) => {
                    error!("Metadata error on {:?}. Skipping {:?}", path, e);
                    continue;
                }
            };
            handle_propfind_path(xmlwriter, &path, &self.serverpath.file_to_url(&path), &meta, props)?;
            // Ignore errors in order to try the other files. This could fail for
            // connection reasons (not file I/O), but those should retrigger and
            // get passed up on subsequent xml writes
            let _ = self.handle_propfind_path_recursive(&path, depth - 1, xmlwriter, props);
        }
        Ok(())
    }

    
    
    fn uri_to_path(&self, path: &str)
                   -> PathBuf {
        let extend_path = path.to_string();
        let extend_path = &extend_path[1..];
        // let extend_path = percent_decode(extend_path.as_bytes())
        //     .decode_utf8_lossy();
        let root_path = self.serverpath.srv_root.to_str().unwrap().to_string();
        let mut full_path = PathBuf::from(root_path);
        full_path.push(extend_path);
        return full_path;
    }

    /*
    fn uri_to_src_dst(&self, path: PathBuf)
                      -> Result<(PathBuf, PathBuf), Error> {
        // Get the source
        let src = path;
        
        // Get the destination
        let dst = req.headers()
            .get("Destination")
            .and_then(|vec| Some(vec.as_bytes()))
            .and_then(|vec| std::str::from_utf8(vec).ok())
            .and_then(|s| url::Url::parse(s).ok())
            .ok_or(Error::BadPath)?;
        let dst = percent_decode(dst.to_string().as_bytes())
            .decode_utf8()
            .map_err(|_| Error::BadPath)
            .and_then(|dst| {
                          self.serverpath
                              .url_to_file(dst.borrow())
                              .ok_or(Error::BadPath)
                      })?;

        if src == dst {
            return Err(Error::BadPath);
        }

        Ok((src, dst))
    }
    */

    fn handle_propfind(&self, path: warp::path::FullPath, depth: u32, body:bytes::Bytes)
            -> Result<Response<String>, warp::http::Error>{

        // let res_sample = include_bytes!("sample01.xml");
        
        debug!("Propfind path: {:?}, depth : {}", path, depth);

        let parse_config = ParserConfig {
            trim_whitespace: true,
            ..Default::default()
        };
        // debug!("==== body start =====");
        // debug!{"{:?}", whole_body};
        // debug!("==== bod

        let body_empty = body.is_empty();
        let mut reader = body.reader();

        //// body에 전달되는 xml 이 없는 경우, 기본 사항을 response 한다.
        if body_empty{
            let default_propfind = include_bytes!("default_propfind.xml");
            let default_byte = Bytes::from_static(default_propfind);
            reader = default_byte.reader();
        }
        
        let xml = xml::reader::EventReader::new_with_config(&mut reader, parse_config);  
        let mut props = Vec::new();

        if let Err(e) = parse_propfind(xml, |prop| { props.push(prop); }) {
            error!("Propfind error {:?}", e);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("".to_string());
        }

        // debug!("Propfind {:?} {:?}", path, props);
        
        let path_buf = PathBuf::from_str(path.as_str()).unwrap();
        let file_path = self.uri_to_path(path.as_str());
        let meta_result = file_path.metadata();
        if meta_result.is_err(){
            error!("Propfind error No meta");
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("".to_string());
        }

        let meta = meta_result.unwrap();
        let mut xmlwriter = EventWriter::new_with_config(Vec::new(),
                                                         EmitterConfig {
                                                             perform_indent: true,
                                                             ..Default::default()
                                                         });
        xmlwriter
            .write(XmlWEvent::StartDocument {
                       version: XmlVersion::Version10,
                       encoding: Some("utf-8"),
                       standalone: None,
                   }).unwrap();
        xmlwriter
            .write(XmlWEvent::start_element("D:multistatus").ns("D", "DAV:")).unwrap();

        
        let _ = handle_propfind_path(&mut xmlwriter, &file_path,
                             &self.serverpath.file_to_url(&path.as_str()),
                             &meta,
                             &props);

        if meta.is_dir() {
            self.handle_propfind_path_recursive(&file_path, depth, &mut xmlwriter, &props).unwrap();
        }
        xmlwriter.write(XmlWEvent::end_element()).unwrap();
        
        let xlm_body: Vec<u8> = xmlwriter.into_inner();
        let xlm_body_str = String::from_utf8(xlm_body).unwrap();

        // let xlm_body2 = xlm_body.clone();
        // let xlm_body_str = String::from_utf8(xlm_body2).unwrap();
        // debug!("==== Propfind Resonse start ====\n");
        // debug!("{}", xlm_body_str);
        // debug!("==== Propfind Resonse End ====\n");
        
        //warp::reply::with_status(with_server, StatusCode::MULTI_STATUS);


        let res = Response::builder()
            .status(StatusCode::MULTI_STATUS)
            .body(xlm_body_str);
        return res;
    }
    
    /*
    async fn handle_get(&self, req: Request<hyper::body::Incoming>) 
            -> Response<BoxBody<Bytes, std::io::Error>>{
        // Get the file
        let path = self.uri_to_path(&req);
        debug!("Get path {:?}", path);
        
        let file = tokio::fs::File::open(path.clone()).await;
        if file.is_err() {
            error!("ERROR: Unable to open file.");
            return make_error_res(StatusCode::NOT_FOUND);
            
        }
        let file = file.unwrap();
        
        let size = file.metadata().await
            .map(|m| m.len())
            .map_err(|e| io_error_to_status(e)).unwrap();

        let reader_stream = ReaderStream::new(file);

        // Convert to http_body_util::BoxBody
        let stream_body = StreamBody::new(reader_stream.map_ok(Frame::data));
        let boxed_body = stream_body.boxed();
    
        // TODO: byte ranges (Accept-Ranges: bytes)
        // Send response
        let mut res = Response::builder()
            .status(StatusCode::OK)
            .body(boxed_body)
            .unwrap();       
            
        let hadermap = res.headers_mut();

        // Ignore size = 0 to hopefully work reasonably with special files
        if size > 0 {
            hadermap.insert(hyper::header::CONTENT_LENGTH, hyper::header::HeaderValue::from(size));
        }
        let guess = mime_guess::from_path(path).first().unwrap();
        let mut context_type = guess.type_().as_str().to_string();
        context_type.push('/');
        context_type.push_str(guess.subtype().as_str());
        if guess.type_().as_str().to_string().eq("text"){
            context_type.push_str("; charset=utf-8");
        }
        hadermap.insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_str(
            &context_type
        ).unwrap());

        return res;

    }
    */
    
    /*
    async fn handle_put(&self, req: Request<hyper::body::Incoming>)
                  -> Response<BoxBody<Bytes, std::io::Error>>{
        let path = self.uri_to_path(&req);
        let file = File::create(path);
        if file.is_err() {
            error!("ERROR: Unable to open file.");
            return make_error_res(StatusCode::NOT_FOUND);
        }
        let mut file = file.unwrap();
        let whole_body = req.collect().await.unwrap();
        let buf = whole_body.to_bytes();
        //whole_body.

        let _ = file.write_all(&buf);

        let res = Response::builder()
            .status(StatusCode::OK)
            .body(Full::new("".into()).map_err(|e| match e {}).boxed())
            .unwrap();       
        return res;
    }

    async fn handle_copy(&self, req: Request<hyper::body::Incoming>)
            -> Response<BoxBody<Bytes, std::io::Error>>{
        let result_path = self.uri_to_src_dst(&req);
        if result_path.is_err() {
            error!("ERROR: Unable to copy file.");
            return make_error_res(StatusCode::NOT_FOUND);
        }
        let (src, dst) = result_path.unwrap();
        debug!("Copy {:?} -> {:?}", src, dst);

        // TODO: handle overwrite flags and directory copies
        // TODO: proper error for out of space
        let ret_copy = std::fs::copy(src, dst);
        if ret_copy.is_err() {
            let err = ret_copy.unwrap_err();
            error!("ERROR: Unable to copy file. {:?}", err);
            return make_error_res(StatusCode::BAD_REQUEST);
        }
        
        let res = Response::builder()
            .status(StatusCode::CREATED)
            .body(Full::new("".into()).map_err(|e| match e {}).boxed())
            .unwrap();       
        return res;
    }

    async fn handle_move(&self, req: Request<hyper::body::Incoming>)
            -> Response<BoxBody<Bytes, std::io::Error>>{
        let result_path = self.uri_to_src_dst(&req);
        if result_path.is_err() {
            error!("ERROR: Unable to copy file.");
            return make_error_res(StatusCode::NOT_FOUND);
        }
        let (src, dst) = result_path.unwrap();
        debug!("Move {:?} -> {:?}", src, dst);

        // TODO: handle overwrite flags
        let ret_copy = std::fs::rename(src, dst);
        if ret_copy.is_err() {
            let err = ret_copy.unwrap_err();
            error!("ERROR: Unable to copy file. , {:?}", err);
            return make_error_res(StatusCode::BAD_REQUEST);
        }
        
        let res = Response::builder()
            .status(StatusCode::CREATED)
            .body(Full::new("".into()).map_err(|e| match e {}).boxed())
            .unwrap();       
        return res;
    }

    async fn handle_delete(&self, req: Request<hyper::body::Incoming>)
            -> Response<BoxBody<Bytes, std::io::Error>>{

        // Get the file
        let path = self.uri_to_path(&req);
        let meta = path.metadata()
            .map_err(|e| io_error_to_status(e)).unwrap();
        
        if meta.is_dir() {
                std::fs::remove_dir_all(path)
            } else {
                std::fs::remove_file(path)
            }
            .map_err(|e| io_error_to_status(e)).unwrap();

        let res = Response::builder()
            .status(StatusCode::OK)
            .body(Full::new("".into()).map_err(|e| match e {}).boxed())
            .unwrap();       
        return res;
    }

    async fn handle_mkdir(&self, req: Request<hyper::body::Incoming>)
            -> Response<BoxBody<Bytes, std::io::Error>>{
        let path = self.uri_to_path(&req);
        let ret = std::fs::create_dir(path);
        let status = match ret {
            Ok(_) => StatusCode::CREATED,
            Err(ref e) if e.kind() == ErrorKind::NotFound => {
                StatusCode::CONFLICT
            }
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let res = Response::builder()
            .status(status)
            .body(Full::new("".into()).map_err(|e| match e {}).boxed())
            .unwrap();       
        return res;
    }

    */
}

pub async fn handle_custom(reject: Rejection) -> Result<impl Reply, Rejection> {
    if reject.find::<MethodError>().is_some() {
        Ok(StatusCode::METHOD_NOT_ALLOWED)
    } else {
        Err(reject)
    }
}

pub fn index_filter() -> impl Filter<Extract = (&'static str,), Error = Rejection> + Clone {
    return warp::path!("index").map(|| "");
}

fn method(name: &'static str) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    warp::method()
        .and_then(move |m: Method| async move {
            if m == name {
                Ok(())
            } else {
                Err(reject::custom(MethodError))
            }
        })
        .untuple_one()
}

pub async fn handle_not_found(reject: Rejection) -> Result<impl Reply, Rejection> {
    if reject.is_not_found() {
        Ok(StatusCode::NOT_FOUND)
    } else {
        Err(reject)
    }
}


pub async fn handle(server:&Server) 
    -> BoxedFilter<(impl Reply,)> {
    debug!("handle");

    let method_option = route_method_option();
    let method_propfind = route_method_propfind(server);
    
    let static_path = server.clone().serverpath.srv_root;
    let asset_filter = warp::path("assets").and(
        warp::fs::dir(static_path)
    );

    let boxed_filter = method_option
        .or(method_propfind)
        .or(asset_filter).boxed();

    return boxed_filter;
    /*
    let reqtype = match req.method().as_str().to_uppercase().as_str(){
        "OPTIONS" => RequestType::Options,
        "GET" => RequestType::Get,
        "PUT" => RequestType::Put,
        "DELETE" => RequestType::Delete,
        "PROPFIND" => RequestType::Propfind,
        "COPY" => RequestType::Copy,
        "MOVE" => RequestType::Move,
        "MKCOL" => RequestType::Mkdir,
        _ => {

            let mut res = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(NOTFOUND.into()).map_err(|e| match e {}).boxed())
                .unwrap();
            *res.status_mut() = StatusCode::NOT_FOUND;
            return Ok(res);
        }
    };

    let res_build = Response::builder();

    let mut result_res = match reqtype {
        RequestType::Options => {
            let mut res = res_build.status(200)
                .body(())
                .unwrap();
            let hadermap = res.headers_mut();
            hadermap.insert(
                hyper::header::ALLOW,
                hyper::header::HeaderValue::from_str("OPTIONS,GET,PUT,DELETE,PROPFIND,COPY,MOVE").unwrap()
            );
            hadermap.insert("DAV", hyper::header::HeaderValue::from_str("1").unwrap());

            let res = Response::builder()
                .status(StatusCode::OK)
                .body(Full::new("".into()).map_err(|e| match e {}).boxed())
                .unwrap();
            return Ok(res);
            
        }
        // RequestType::Propfind =>{
        //     server.handle_propfind(req).await
        // }
        RequestType::Get => {
            server.handle_get(req).await
        },
        // RequestType::Put => {
        //     server.handle_put(req).await
        // },
        // RequestType::Copy => {
        //     server.handle_copy(req).await
        // },
        // RequestType::Move => {
        //     server.handle_move(req).await
        // },
        // RequestType::Delete => {
        //     server.handle_delete(req).await
        // },
        // RequestType::Mkdir => {
        //     server.handle_mkdir(req).await
        // },
        // _=>{
        //     error!("Request error");
        //     let res = Response::builder()
        //         .status(StatusCode::NOT_FOUND)
        //         .body(Full::new(BAD_REQUEST.into()).map_err(|e| match e {}).boxed())
        //         .unwrap();
        //     return Ok(res);
        // }
    };

    let hadermap = result_res.headers_mut();
    hadermap.insert(hyper::header::CACHE_CONTROL, 
        hyper::header::HeaderValue::from_str("no-cache").unwrap());
    hadermap.insert(hyper::header::PRAGMA, 
        hyper::header::HeaderValue::from_str("no-cache").unwrap());
    // hadermap.insert(hyper::header::CONTENT_TYPE, 
    //     hyper::header::HeaderValue::from_str("text/xml; charset=\"utf-8\"").unwrap());
    
    return Ok(result_res);
    */
}

