//! Bound the wallet's descriptor namespace before loading a profile or starting
//! threads. Node raises its soft limit to roughly a million on macOS; scanning
//! that namespace before every restricted exec otherwise costs ~120 ms here.
//! This single-profile, serial worker needs far fewer descriptors than 8192.

pub(crate) const DESCRIPTORS: libc::rlim_t = 8192;

pub(crate) fn bound_descriptor_limit() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // Only this newly started wallet process changes. Keep the hard limit and
    // any lower operator limit. Existing high descriptors remain open, so child
    // cleanup must cover /dev/fd as well as the new soft-limit namespace.
    // This is an optimization: failure retains the previous full scan.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 && limit.rlim_cur > DESCRIPTORS {
            limit.rlim_cur = DESCRIPTORS;
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn startup_preserves_lower_soft_limits_and_the_hard_limit() {
        const MARKER: &str = "ZARK_TEST_MAC_DESCRIPTOR_LIMIT";
        if let Ok(soft) = std::env::var(MARKER) {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
                0
            );
            limit.rlim_cur = soft.parse().unwrap();
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
            bound_descriptor_limit();
            let mut actual = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut actual) },
                0
            );
            assert_eq!(actual.rlim_cur, limit.rlim_cur.min(DESCRIPTORS));
            assert_eq!(actual.rlim_max, limit.rlim_max);
            return;
        }
        // Never change the limit of the concurrent test runner itself.
        for soft in [512, 16384] {
            assert!(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "cli::macos::tests::startup_preserves_lower_soft_limits_and_the_hard_limit"
                    ])
                    .env(MARKER, soft.to_string())
                    .status()
                    .unwrap()
                    .success()
            );
        }
    }
}
