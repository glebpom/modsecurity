#[repr(C)]
pub struct ModSecurityInterventionBridge {
    pub status: i32,
    pub pause: i32,
    pub url: *const std::os::raw::c_char,
    pub log: *const std::os::raw::c_char,
    pub disruptive: i32,
}

unsafe impl cxx::ExternType for ModSecurityInterventionBridge {
    type Id = cxx::type_id!("modsecurity::ModSecurityIntervention");
    type Kind = cxx::kind::Opaque;
}

#[cxx::bridge(namespace = "modsecurity")]
mod ffi {

    unsafe extern "C++" {
        include!("wrapper.h");
        include!("modsecurity/rules.h");

        type Rules;
        fn new_rules() -> UniquePtr<Rules>;
        fn dump(self: Pin<&mut Rules>);

        unsafe fn load(self: Pin<&mut Rules>, rules: *const c_char, reference: &CxxString) -> i32;

        fn get_parser_error(rules: Pin<&mut Rules>) -> UniquePtr<CxxString>;
    }

    unsafe extern "C++" {
        include!("wrapper.h");
        include!("modsecurity/modsecurity.h");

        type ModSecurity;

        fn new_modsecurity() -> UniquePtr<ModSecurity>;
    }

    unsafe extern "C++" {
        // include!("rust_cxx_bindings.h");
        include!("modsecurity/intervention.h");

        type ModSecurityIntervention = crate::ffi::ModSecurityInterventionBridge;
    }

    unsafe extern "C++" {
        include!("wrapper.h");
        include!("modsecurity/transaction.h");

        type Transaction;

        fn new_transaction(
            mod_security: Pin<&mut ModSecurity>,
            rules: Pin<&mut Rules>,
        ) -> UniquePtr<Transaction>;

        fn processRequestHeaders(self: Pin<&mut Transaction>) -> i32;
        unsafe fn addRequestHeader(
            self: Pin<&mut Transaction>,
            key: *const u8,
            key_len: usize,
            value: *const u8,
            value_len: usize,
        ) -> i32;

        fn processResponseHeaders(self: Pin<&mut Transaction>, code: i32, proto: &CxxString)
            -> i32;
        unsafe fn addResponseHeader(
            self: Pin<&mut Transaction>,
            name: *const u8,
            key_len: usize,
            value: *const u8,
            value_len: usize,
        ) -> i32;

        fn processResponseBody(self: Pin<&mut Transaction>) -> i32;
        unsafe fn appendResponseBody(
            self: Pin<&mut Transaction>,
            body: *const u8,
            len: usize,
        ) -> i32;

        fn processRequestBody(self: Pin<&mut Transaction>) -> i32;
        unsafe fn appendRequestBody(
            self: Pin<&mut Transaction>,
            body: *const u8,
            len: usize,
        ) -> i32;

        unsafe fn processConnection(
            self: Pin<&mut Transaction>,
            client: *const c_char,
            cPort: i32,
            server: *const c_char,
            sPort: i32,
        ) -> i32;
        unsafe fn processURI(
            self: Pin<&mut Transaction>,
            uri: *const c_char,
            protocol: *const c_char,
            http_version: *const c_char,
        ) -> i32;

        unsafe fn intervention(
            self: Pin<&mut Transaction>,
            intervention: *mut ModSecurityIntervention,
        ) -> bool;
    }
}

pub use ffi::*;
