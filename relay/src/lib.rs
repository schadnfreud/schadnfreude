use std::ffi::CStr;
pub mod apisrv;
#[macro_use]
pub mod httpsrv;
pub mod nodesrv;
pub mod client;
pub mod sflogger;
pub mod stream;
pub mod tube;
pub mod sodiumffi;
pub mod sferr;
pub mod tests;
pub mod innermain;
pub use innermain::*;
pub use serde_json::json;
pub use serde_json::Value;
pub use sflogger::*;
#[no_mangle]
pub extern "C" fn runsf(argc: usize, argv: *const *mut std::os::raw::c_char) -> usize {
    let mut argvec = Vec::with_capacity(argc);
    unsafe {
        for argptr in std::slice::from_raw_parts(argv, argc) {
            if let Ok(argstr) = CStr::from_ptr(*argptr).to_str() {
                argvec.push(argstr.to_string());
            } else {
                return 1;
            }
        }
    }
    innermain::innermain(argvec).unwrap_or(2)
}
