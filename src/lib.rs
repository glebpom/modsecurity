pub mod ffi;

use cxx::let_cxx_string;
use cxx::{UniquePtr};
use http::{HeaderMap, Request, Response, StatusCode, Version};
use std::convert::TryInto;
use std::ffi::{CStr, CString, NulError};
use std::net::{SocketAddr};
use std::ptr::null;
use std::str::FromStr;
use std::time::Duration;
use lazy_static::lazy_static;
use std::sync::{Arc, Mutex};

lazy_static! {
    static ref RULES_LOCK: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
}

macro_rules! invoke_native {
    ($ex:expr) => {
        let ret = $ex;
        if ret == 1 {
            return Ok(());
        } else {
            return Err(Error::Failure);
        }
    };
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("string error: {_0}")]
    String(#[from] NulError),

    #[error("{_0}")]
    ModSecurity(String),

    #[error("operation failure")]
    Failure,

    #[error("unknown protocol")]
    UnsupportedProtocol,
}

/// ModSecurity instance
pub struct ModSecurity {
    native: UniquePtr<ffi::ModSecurity>,
}

impl ModSecurity {
    /// Create new ModSecurity instance
    pub fn new() -> Self {
        ModSecurity {
            native: ffi::new_modsecurity(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Intervention {
    status: StatusCode,
    pause: Duration,
    redirect_to: Option<http::Uri>,
    log: Option<String>,
    disruptive: bool,
}

/// Rules instance
pub struct Rules {
    native: UniquePtr<ffi::Rules>,
}

impl Rules {
    /// Create new Rules instance
    pub fn new() -> Self {
        Rules {
            native: ffi::new_rules(),
        }
    }

    /// Dump rules
    pub fn dump(&mut self) {
        self.native.as_mut().unwrap().dump();
    }

    fn get_parser_error(&mut self) -> String {
        ffi::get_parser_error(self.native.as_mut().unwrap()).to_string()
    }

    /// Add rules from string
    pub fn add(&mut self, rules_str: &str, reference: &str) -> Result<(), Error> {
        let _lock = RULES_LOCK.lock().unwrap();

        let native = self.native.as_mut().unwrap();
        let rules = CString::new(rules_str)?;

        let_cxx_string!(cpp_reference = reference);

        let ret = unsafe { native.load(rules.as_ptr() as *const i8, &cpp_reference) };
        if ret < 0 {
            let msg = self.get_parser_error();
            return Err(Error::ModSecurity(msg));
        }

        Ok(())
    }
}

/// Transaction instance
pub struct Transaction {
    native: UniquePtr<ffi::Transaction>,
}

impl Transaction {
    /// Create new Transaction instance
    pub fn new(modsec: &mut ModSecurity, rules: &mut Rules) -> Self {
        Transaction {
            native: ffi::new_transaction(
                modsec.native.as_mut().unwrap(),
                rules.native.as_mut().unwrap(),
            ),
        }
    }

    pub fn add_request_header(
        &mut self,
        name: &http::header::HeaderName,
        value: &http::header::HeaderValue,
    ) -> Result<(), Error> {
        let name_bytes: &[u8] = name.as_ref();
        let value_bytes: &[u8] = value.as_ref();

        let native = self.native.as_mut().unwrap();

        invoke_native!(unsafe {
            native.addRequestHeader(
                name_bytes.as_ptr(),
                name_bytes.len(),
                value_bytes.as_ptr(),
                value_bytes.len(),
            )
        });
    }

    /// Add all response headers from HeaderMap
    pub fn add_response_headers(&mut self, headers: &HeaderMap) -> Result<(), Error> {
        for (name, value) in headers.iter() {
            self.add_response_header(name, value)?;
        }

        Ok(())
    }

    /// Add all request headers from HeaderMap
    pub fn add_request_headers(&mut self, headers: &HeaderMap) -> Result<(), Error> {
        for (name, value) in headers.iter() {
            self.add_request_header(name, value)?;
        }

        Ok(())
    }

    pub fn add_response_header(
        &mut self,
        name: &http::header::HeaderName,
        value: &http::header::HeaderValue,
    ) -> Result<(), Error> {
        let name_bytes: &[u8] = name.as_ref();
        let value_bytes: &[u8] = value.as_ref();

        let native = self.native.as_mut().unwrap();

        invoke_native!(unsafe {
            native.addResponseHeader(
                name_bytes.as_ptr(),
                name_bytes.len(),
                value_bytes.as_ptr(),
                value_bytes.len(),
            )
        });
    }

    pub fn process_uri(
        &mut self,
        uri: &http::Uri,
        method: &http::Method,
        http_version: &http::Version,
    ) -> Result<(), Error> {
        let native = self.native.as_mut().unwrap();

        let uri = CString::new(uri.to_string())?;
        let method = CString::new(method.as_str())?;

        let version = CString::new(match http_version {
            &Version::HTTP_2 => "2",
            &Version::HTTP_11 => "1.1",
            &Version::HTTP_10 => "1.0",
            &Version::HTTP_09 => "0.9",
            _ => return Err(Error::UnsupportedProtocol),
        })?;

        invoke_native!(unsafe {
            native.processURI(uri.as_ptr(), method.as_ptr(), version.as_ptr())
        });
    }

    pub fn process_connection(
        &mut self,
        client_addr: &SocketAddr,
        server_addr: &SocketAddr,
    ) -> Result<(), Error> {
        let native = self.native.as_mut().unwrap();

        let client_ip = CString::new(client_addr.ip().to_string())?;
        let server_ip = CString::new(client_addr.ip().to_string())?;
        let client_port = client_addr.port();
        let server_port = server_addr.port();

        invoke_native!(unsafe {
            native.processConnection(
                client_ip.as_ptr(),
                client_port.into(),
                server_ip.as_ptr(),
                server_port.into(),
            )
        });
    }

    pub fn append_response_body(&mut self, buf: &[u8]) -> Result<(), Error> {
        let native = self.native.as_mut().unwrap();

        invoke_native!(unsafe { native.appendResponseBody(buf.as_ptr(), buf.len()) });
    }

    pub fn append_request_body(&mut self, buf: &[u8]) -> Result<(), Error> {
        let native = self.native.as_mut().unwrap();

        invoke_native!(unsafe { native.appendRequestBody(buf.as_ptr(), buf.len()) });
    }

    pub fn process_request_body(&mut self) -> Result<(), Error> {
        let native = self.native.as_mut().unwrap();

        invoke_native!(native.processRequestBody());
    }

    pub fn process_response_body(&mut self) -> Result<(), Error> {
        let native = self.native.as_mut().unwrap();

        invoke_native!(native.processResponseBody());
    }

    pub fn process_request_headers(&mut self) -> Result<(), Error> {
        let native = self.native.as_mut().unwrap();

        invoke_native!(native.processRequestHeaders());
    }

    pub fn process_response_headers(
        &mut self,
        status_code: &StatusCode,
        http_version: &http::Version,
    ) -> Result<(), Error> {
        let native = self.native.as_mut().unwrap();

        let proto = match http_version {
            &Version::HTTP_3 => "HTTP 3",
            &Version::HTTP_2 => "HTTP 2",
            &Version::HTTP_11 => "HTTP 1.1",
            &Version::HTTP_10 => "HTTP 1.0",
            &Version::HTTP_09 => "HTTP 0.9",
            _ => return Err(Error::UnsupportedProtocol),
        };

        let_cxx_string!(proto = proto);

        invoke_native!(native.processResponseHeaders(status_code.as_u16().into(), &proto));
    }

    pub fn intervention(&mut self) -> Option<Intervention> {
        let native = self.native.as_mut().unwrap();

        let mut native_intervention = crate::ffi::ModSecurityInterventionBridge {
            status: 200,
            pause: 0,
            url: null(),
            log: null(),
            disruptive: 0,
        };
        let is_intervented = unsafe { native.intervention(&mut native_intervention) };
        if is_intervented {
            let log = if !native_intervention.log.is_null() {
                Some(
                    unsafe { CStr::from_ptr(native_intervention.log) }
                        .to_str()
                        .unwrap()
                        .to_string(),
                )
            } else {
                None
            };

            let uri = if !native_intervention.url.is_null() {
                Some(
                    http::Uri::from_str(
                        unsafe { CStr::from_ptr(native_intervention.url) }
                            .to_str()
                            .unwrap(),
                    )
                        .unwrap(),
                )
            } else {
                None
            };

            Some(Intervention {
                status: StatusCode::from_u16(native_intervention.status.try_into().unwrap())
                    .unwrap(),
                pause: Duration::from_millis(native_intervention.pause.try_into().unwrap()),
                redirect_to: uri,
                log,
                disruptive: native_intervention.disruptive == 1,
            })
        } else {
            None
        }
    }

    /// Process HTTP request. Handle URI, Method, HTTP version, and request Headers.
    /// Doesn't deal with body.
    pub fn check_request<T>(&mut self, req: &Request<T>) -> Result<(), Error> {
        self.process_uri(req.uri(), req.method(), &req.version())?;
        self.add_request_headers(req.headers())?;
        self.process_request_headers()?;

        Ok(())
    }

    /// Process HTTP response. Handle Status Code, HTTP version, and response Headers.
    /// Doesn't deal with body.
    pub fn check_response<T>(&mut self, res: &Response<T>) -> Result<(), Error> {
        self.add_response_headers(res.headers())?;
        self.process_response_headers(&res.status(), &res.version())?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use http::header::HOST;
    use http::Method;

    #[test]
    pub fn test_init_modsecurity() {
        let _modsec = ModSecurity::new();
    }

    #[test]
    pub fn test_rules() {
        let mut rules = Rules::new();
        assert!(rules.add("asd", "ref1").is_err());
        let mut rules = Rules::new();
        rules
            .add(
                r#"SecRule ARGS:ip ";" "t:none,log,deny,msg:'semi colon test',id:2""#,
                "ref2",
            )
            .unwrap();
        let mut rules = Rules::new();
        rules.add(r#"
SecRule FILES "(?i)\.php$" "t:none,log,redirect:http://cyberis.co.uk,msg:'PHP file upload blocked',id:1"
SecRule ARGS:ip ";" "t:none,log,deny,msg:'semi colon test',id:2"
"#, "ref3").unwrap();
        rules.dump();
    }

    #[test]
    pub fn test_transaction() {
        let mut modsec = ModSecurity::new();
        let mut rules = Rules::new();
        let mut transaction = Transaction::new(&mut modsec, &mut rules);
        transaction
            .process_connection(
                &"127.0.0.1:1232".parse().unwrap(),
                &"10.20.30.40:45212".parse().unwrap(),
            )
            .unwrap();
        transaction
            .process_uri(
                &"https://example.com/path?query=param".parse().unwrap(),
                &Method::GET,
                &Version::HTTP_11,
            )
            .unwrap();
        transaction
            .add_request_header(&http::header::ACCEPT, &"text/html".parse().unwrap())
            .unwrap();
        transaction.process_request_headers().unwrap();
        transaction.append_request_body("request".as_ref()).unwrap();
        transaction.process_request_body().unwrap();
        transaction
            .add_response_header(&http::header::CONTENT_TYPE, &"text/html".parse().unwrap())
            .unwrap();
        transaction
            .process_response_headers(&StatusCode::CREATED, &Version::HTTP_2)
            .unwrap();
        transaction
            .append_response_body("response".as_ref())
            .unwrap();
        transaction.process_response_body().unwrap();
        assert!(transaction.intervention().is_none());
    }

    #[test]
    pub fn test_intervention() {
        let mut modsec = ModSecurity::new();
        let mut rules = Rules::new();
        rules
            .add(
                r#"
SecRuleEngine On
SecDefaultAction "phase:1,log,block,deny,status:400"
SecRule REQUEST_URI "/path1" "phase:1,block,id:5"
"#,
                "test",
            )
            .unwrap();

        let mut transaction = Transaction::new(&mut modsec, &mut rules);
        transaction
            .process_connection(
                &"127.0.0.1:1232".parse().unwrap(),
                &"10.20.30.40:45212".parse().unwrap(),
            )
            .unwrap();
        transaction
            .process_uri(
                &"https://example.com/path1".parse().unwrap(),
                &Method::GET,
                &Version::HTTP_11,
            )
            .unwrap();
        transaction
            .add_request_header(&HOST, &"example.com".parse().unwrap())
            .unwrap();
        transaction.process_request_headers().unwrap();
        let intervented = transaction.intervention().unwrap();
        assert_eq!(intervented.status, StatusCode::BAD_REQUEST);
        assert!(intervented.redirect_to.is_none());
        assert!(intervented.disruptive);
    }
}
