#[macro_use]
pub mod innermain;
pub use innermain::*;
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
pub use serde_json::json;
pub use serde_json::Value;
pub use sflogger::*;
//Entry point
fn main() -> SfRes<()> {
    innermain(env::args().collect())?; //call innermain with cli args
    Ok(())
}
