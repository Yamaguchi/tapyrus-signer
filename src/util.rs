use secp256k1::PublicKey;
use std::convert::TryFrom;
use std::os::raw::c_int;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

pub fn sum_point(points: &Vec<PublicKey>) -> PublicKey {
    let mut iter = points.iter();
    let head = iter.next().unwrap();
    let tail = iter;
    tail.fold(head.clone(), |sum, point| {
        sum.combine(&point).expect("failed to combine PublicKey")
    })
}

const STOP_SIGNALS: [usize; 6] = [
    signal_hook::SIGABRT as usize,
    signal_hook::SIGHUP as usize,
    signal_hook::SIGINT as usize,
    signal_hook::SIGQUIT as usize,
    signal_hook::SIGTERM as usize,
    signal_hook::SIGTRAP as usize,
];

pub fn set_stop_signal_handler() -> Result<Arc<AtomicUsize>, std::io::Error> {
    let handler = Arc::new(AtomicUsize::new(0));

    for signal in &STOP_SIGNALS {
        signal_hook::flag::register_usize(
            *signal as c_int,
            Arc::clone(&handler),
            *signal as usize,
        )?;
    }
    Ok(handler)
}

pub fn signal_to_string(signal: usize) -> &'static str {
    let signal: u32 = TryFrom::try_from(signal).unwrap();
    match signal as i32 {
        signal_hook::SIGABRT => "SIGABRT",
        signal_hook::SIGHUP => "SIGHUP",
        signal_hook::SIGINT => "SIGINT",
        signal_hook::SIGQUIT => "SIGQUIT",
        signal_hook::SIGTERM => "SIGTERM",
        signal_hook::SIGTRAP => "SIGTRAP",
        _ => unreachable!("unregistered signal received"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::constants::{GENERATOR_X, GENERATOR_Y};
    use std::sync::atomic::Ordering;

    #[test]
    fn test_sum_point() {
        // scalar values
        let s1 = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ];
        let s2 = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 2,
        ];
        let s3 = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 3,
        ];

        let mut v = vec![4 as u8];
        v.extend(GENERATOR_X.as_ref());
        v.extend(GENERATOR_Y.as_ref());
        let generator = PublicKey::from_slice(&v).unwrap();

        // point
        let secp = secp256k1::Secp256k1::new();
        let mut p1 = generator;
        p1.mul_assign(&secp, &s1).unwrap();
        let mut p2 = generator;
        p2.mul_assign(&secp, &s2).unwrap();
        let mut p3 = generator;
        p3.mul_assign(&secp, &s3).unwrap();

        let sum = sum_point(&vec![p1, p2, p3]);

        let s6 = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 6,
        ];
        let mut p6 = generator;
        p6.mul_assign(&secp, &s6).unwrap();
        assert_eq!(sum, p6);
    }

    #[test]
    fn test_signals() {
        let handler = set_stop_signal_handler().unwrap();

        unsafe {
            libc::raise(signal_hook::SIGINT);
            assert_eq!(
                handler.load(Ordering::Relaxed),
                signal_hook::SIGINT as usize
            );

            libc::raise(signal_hook::SIGABRT);
            assert_eq!(
                handler.load(Ordering::Relaxed),
                signal_hook::SIGABRT as usize
            );

            libc::raise(signal_hook::SIGHUP);
            assert_eq!(
                handler.load(Ordering::Relaxed),
                signal_hook::SIGHUP as usize
            );

            libc::raise(signal_hook::SIGQUIT);
            assert_eq!(
                handler.load(Ordering::Relaxed),
                signal_hook::SIGQUIT as usize
            );

            libc::raise(signal_hook::SIGTERM);
            assert_eq!(
                handler.load(Ordering::Relaxed),
                signal_hook::SIGTERM as usize
            );

            libc::raise(signal_hook::SIGTRAP);
            assert_eq!(
                handler.load(Ordering::Relaxed),
                signal_hook::SIGTRAP as usize
            );
        }
    }
}
