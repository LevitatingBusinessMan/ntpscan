use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;

pub static LEVEL: AtomicU8 = AtomicU8::new(0);

/**
 * 0 is the default
 * 1 is verbose
 * 2 is very verbose
 */
pub fn set_level(level: u8) {
    LEVEL.store(level, Ordering::Relaxed);
}

#[macro_export]
macro_rules! vprintln {
    ($($arg:tt)*) => {
        if $crate::log::LEVEL.load(std::sync::atomic::Ordering::Relaxed) > 0 {
            println!($($arg)*);
}    };
}

#[macro_export]
macro_rules! vvprintln {
    ($($arg:tt)*) => {
        if $crate::log::LEVEL.load(std::sync::atomic::Ordering::Relaxed) > 1 {
            println!($($arg)*);
        }
    };
}
