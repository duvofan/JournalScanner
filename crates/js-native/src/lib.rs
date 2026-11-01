#![allow(
    clippy::needless_range_loop,
    clippy::explicit_counter_loop,
    clippy::manual_range_contains,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::needless_late_init,
    clippy::collapsible_else_if,
    clippy::manual_abs_diff,
    clippy::manual_clamp,
    clippy::field_reassign_with_default,
    clippy::manual_is_multiple_of,
    clippy::chunks_exact_to_as_chunks,
    clippy::map_entry,
    clippy::manual_repeat_n,
    clippy::unnecessary_sort_by
)]

pub mod analysis;
pub mod analyze;
pub mod classfile;
pub mod hidden;
pub mod jbytecode;
mod jf_data;
mod pat_data;
pub mod patterns;
pub mod payload;
pub mod pe;
pub mod score;
pub mod util;

#[cfg(windows)]
mod ctx;
#[cfg(windows)]
mod disk;
#[cfg(windows)]
mod flow;
#[cfg(windows)]
mod hooks;
#[cfg(windows)]
mod memscan;
#[cfg(windows)]
mod phases;
#[cfg(windows)]
mod winutil;

#[cfg(windows)]
pub fn run(args: Vec<String>) -> i32 {
    flow::run_main(args)
}

#[cfg(not(windows))]
pub fn run(_args: Vec<String>) -> i32 {
    1
}
