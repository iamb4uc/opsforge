use anyhow::{Context, Result};
use std::{
    io,
    os::unix::process::CommandExt,
    process::{Child, ChildStdout, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

static CANCELLED: OnceLock<Arc<AtomicUsize>> = OnceLock::new();

fn flag() -> &'static Arc<AtomicUsize> {
    CANCELLED.get_or_init(|| Arc::new(AtomicUsize::new(0)))
}

pub fn install_signal_handlers() -> Result<()> {
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register_usize(signal, Arc::clone(flag()), signal as usize)?;
    }
    Ok(())
}

pub(crate) fn cancel() {
    flag().store(1, Ordering::Relaxed);
}

pub(crate) fn check_cancelled() -> Result<()> {
    let reason = match flag().load(Ordering::Relaxed) {
        0 => return Ok(()),
        1 => "collection cancelled by TUI Ctrl-C",
        2 => "collection cancelled by SIGINT",
        15 => "collection cancelled by SIGTERM",
        _ => "collection cancelled by signal",
    };
    Err(io::Error::new(io::ErrorKind::Interrupted, reason).into())
}

fn signal_group(pid: u32, signal: &str) -> bool {
    Command::new("kill")
        .args([signal, "--", &format!("-{pid}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

pub(crate) struct OwnedChild {
    child: Arc<Mutex<Child>>,
    finished: Arc<AtomicBool>,
    watcher: Option<JoinHandle<()>>,
}

impl OwnedChild {
    pub(crate) fn spawn(command: &mut Command) -> Result<Self> {
        check_cancelled()?;
        Self::start(command, Arc::clone(flag()))
    }

    fn start(command: &mut Command, cancelled: Arc<AtomicUsize>) -> Result<Self> {
        let child = Arc::new(Mutex::new(command.process_group(0).spawn()?));
        let finished = Arc::new(AtomicBool::new(false));
        let watched_child = Arc::clone(&child);
        let watched_finished = Arc::clone(&finished);
        let watcher = thread::spawn(move || {
            let mut started = None;
            let mut previous = None;
            while !watched_finished.load(Ordering::Relaxed) {
                if cancelled.load(Ordering::Relaxed) != 0 {
                    let elapsed = started.get_or_insert_with(Instant::now).elapsed();
                    let signal = if elapsed >= Duration::from_secs(2) {
                        "-KILL"
                    } else if elapsed >= Duration::from_secs(1) {
                        "-TERM"
                    } else {
                        "-INT"
                    };
                    if previous != Some(signal) {
                        // The lock prevents reaping and PID reuse before signalling the owned group.
                        let mut child = watched_child
                            .lock()
                            .unwrap_or_else(|error| error.into_inner());
                        if watched_finished.load(Ordering::Relaxed) {
                            break;
                        }
                        if !signal_group(child.id(), signal) {
                            let _ = child.kill();
                        }
                        previous = Some(signal);
                    }
                }
                thread::sleep(Duration::from_millis(50));
            }
        });
        Ok(Self {
            child,
            finished,
            watcher: Some(watcher),
        })
    }

    pub(crate) fn take_stdout(&self) -> Result<ChildStdout> {
        self.child
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .stdout
            .take()
            .context("collector child stdout")
    }

    pub(crate) fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
        let mut child = self.child.lock().unwrap_or_else(|error| error.into_inner());
        let status = child.try_wait()?;
        if status.is_some() {
            self.finished.store(true, Ordering::Relaxed);
        }
        Ok(status)
    }

    pub(crate) fn wait(&self) -> io::Result<ExitStatus> {
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        {
            let mut child = self.child.lock().unwrap_or_else(|error| error.into_inner());
            if !self.finished.swap(true, Ordering::Relaxed) {
                signal_group(child.id(), "-TERM");
                thread::sleep(Duration::from_millis(100));
                signal_group(child.id(), "-KILL");
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    #[test]
    fn cancellation_unblocks_a_pipe_and_stops_the_owned_process_group() {
        let cancelled = Arc::new(AtomicUsize::new(0));
        let child = OwnedChild::start(
            Command::new("sh")
                .args(["-c", "sleep 30 & printf '%s\\n' $!; wait"])
                .stdout(Stdio::piped()),
            Arc::clone(&cancelled),
        )
        .expect("owned child");
        let mut output = BufReader::new(child.take_stdout().expect("stdout"));
        let mut pid = String::new();
        output.read_line(&mut pid).expect("child pid");
        let pid: u32 = pid.trim().parse().expect("numeric pid");
        cancelled.store(2, Ordering::Relaxed);
        let started = Instant::now();
        let mut remainder = String::new();
        assert_eq!(output.read_line(&mut remainder).expect("pipe closes"), 0);
        assert!(!child.wait().expect("reaped").success());
        assert!(started.elapsed() < Duration::from_secs(5));
        if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            assert_eq!(
                stat.rsplit_once(") ")
                    .expect("proc state")
                    .1
                    .split_whitespace()
                    .next(),
                Some("Z")
            );
        }
    }
}
