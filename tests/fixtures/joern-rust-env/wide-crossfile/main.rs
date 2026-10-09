mod service;
mod repository;
mod stage_a;
mod stage_b;
fn main() {
 let value = std::env::var("TRACEPROOF_COMMAND").unwrap();
 service::dispatch(value);
}
