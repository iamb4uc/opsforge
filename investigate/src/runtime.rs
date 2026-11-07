#[cfg(unix)]
use std::time::Instant;
#[cfg(unix)]
use std::{
    os::unix::process::CommandExt,
    process::{Child, Stdio},
};
#[cfg(windows)]
type Child = Box<dyn process_wrap::std::ChildWrapper>;
use anyhow::{Context, Result};
use std::{
    io,
    process::{ChildStdout, Command, ExitStatus},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

static CANCELLED: OnceLock<Arc<AtomicUsize>> = OnceLock::new();

fn flag() -> &'static Arc<AtomicUsize> {
    CANCELLED.get_or_init(|| Arc::new(AtomicUsize::new(0)))
}

#[cfg(unix)]
pub fn install_signal_handlers() -> Result<()> {
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register_usize(signal, Arc::clone(flag()), signal as usize)?;
    }
    Ok(())
}

#[cfg(windows)]
pub fn install_signal_handlers() -> Result<()> {
    ctrlc::set_handler(|| flag().store(2, Ordering::Relaxed))?;
    Ok(())
}

#[cfg(unix)]
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

#[cfg(unix)]
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
    cancelled: Arc<AtomicUsize>,
    terminated: Arc<AtomicBool>,
    watcher: Option<JoinHandle<()>>,
}

impl OwnedChild {
    pub(crate) fn spawn(command: &mut Command) -> Result<Self> {
        check_cancelled()?;
        Self::start(command, Arc::clone(flag()))
    }

    fn start(command: &mut Command, cancelled: Arc<AtomicUsize>) -> Result<Self> {
        #[cfg(unix)]
        let child = command.process_group(0).spawn()?;
        #[cfg(windows)]
        let child = {
            use process_wrap::std::{CommandWrap, JobObject};
            let command = std::mem::replace(command, Command::new(""));
            CommandWrap::from(command).wrap(JobObject).spawn()?
        };
        let child = Arc::new(Mutex::new(child));
        let finished = Arc::new(AtomicBool::new(false));
        let mut owned = Self {
            child,
            finished,
            cancelled,
            terminated: Arc::new(AtomicBool::new(false)),
            watcher: None,
        };
        let watched_child = Arc::clone(&owned.child);
        let watched_finished = Arc::clone(&owned.finished);
        let cancelled = Arc::clone(&owned.cancelled);
        let terminated = Arc::clone(&owned.terminated);
        let watcher = thread::Builder::new().spawn(move || {
            #[cfg(unix)]
            let mut started = None;
            let mut previous = None;
            while !watched_finished.load(Ordering::Relaxed) {
                if cancelled.load(Ordering::Relaxed) != 0 {
                    #[cfg(unix)]
                    let elapsed = started.get_or_insert_with(Instant::now).elapsed();
                    #[cfg(unix)]
                    let signal = if elapsed >= Duration::from_secs(2) {
                        "-KILL"
                    } else if elapsed >= Duration::from_secs(1) {
                        "-TERM"
                    } else {
                        "-INT"
                    };
                    #[cfg(windows)]
                    let signal = "-KILL";
                    if previous != Some(signal) {
                        // The lock prevents reaping and PID reuse before signalling the owned group.
                        let mut child = watched_child
                            .lock()
                            .unwrap_or_else(|error| error.into_inner());
                        if watched_finished.load(Ordering::Relaxed) {
                            break;
                        }
                        stop_child(&mut child, signal);
                        if signal == "-KILL" {
                            terminated.store(true, Ordering::Relaxed);
                        }
                        previous = Some(signal);
                    }
                }
                thread::sleep(Duration::from_millis(50));
            }
        })?;
        owned.watcher = Some(watcher);
        Ok(owned)
    }

    pub(crate) fn take_stdout(&self) -> Result<ChildStdout> {
        let mut child = self.child.lock().unwrap_or_else(|error| error.into_inner());
        #[cfg(unix)]
        let stdout = child.stdout.take();
        #[cfg(windows)]
        let stdout = child.stdout().take();
        stdout.context("collector child stdout")
    }

    pub(crate) fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
        let mut child = self.child.lock().unwrap_or_else(|error| error.into_inner());
        if !self.finished.load(Ordering::Relaxed)
            && self.cancelled.load(Ordering::Relaxed) != 0
            && !self.terminated.load(Ordering::Relaxed)
        {
            return Ok(None);
        }
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
            // A Windows group leader can exit while descendants still belong to its job.
            #[cfg(windows)]
            stop_child(&mut child, "-KILL");
            if !self.finished.swap(true, Ordering::Relaxed) {
                stop_child(&mut child, "-TERM");
                thread::sleep(Duration::from_millis(100));
                stop_child(&mut child, "-KILL");
                let _ = child.wait();
            }
        }
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.join();
        }
    }
}

#[cfg(all(test, unix))]
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
        loop {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
            if stat
                .as_ref()
                .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
                || stat.as_ref().is_ok_and(|stat| {
                    stat.rsplit_once(") ")
                        .expect("proc state")
                        .1
                        .split_whitespace()
                        .next()
                        == Some("Z")
                })
            {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "owned child did not exit"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn cancellation_kills_a_signal_ignoring_child_before_reaping_its_parent() {
        let path = std::env::temp_dir().join(format!("opsforge-child-pid-{}", std::process::id()));
        let cancelled = Arc::new(AtomicUsize::new(0));
        let child = OwnedChild::start(
            Command::new("sh")
                .args([
                    "-c",
                    "trap '' INT; (trap '' TERM; sleep 30) & printf '%s\\n' $! > \"$1\"; wait",
                    "sh",
                ])
                .arg(&path)
                .stdout(Stdio::null()),
            Arc::clone(&cancelled),
        )
        .expect("owned process group");
        let started = Instant::now();
        let pid: u32 = loop {
            if let Ok(text) = std::fs::read_to_string(&path)
                && let Ok(pid) = text.trim().parse()
            {
                break pid;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "child did not start"
            );
            thread::sleep(Duration::from_millis(10));
        };
        cancelled.store(15, Ordering::Relaxed);
        assert!(!child.wait().expect("reaped parent").success());
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
            if stat
                .as_ref()
                .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
                || stat.as_ref().is_ok_and(|stat| {
                    stat.rsplit_once(") ")
                        .expect("proc state")
                        .1
                        .split_whitespace()
                        .next()
                        == Some("Z")
                })
            {
                break;
            }
            if Instant::now() >= deadline {
                let _ = Command::new("kill")
                    .args(["-KILL", &pid.to_string()])
                    .status();
                panic!("signal-ignoring owned child survived cancellation");
            }
            thread::sleep(Duration::from_millis(10));
        }
        std::fs::remove_file(path).expect("remove owned pid fixture");
    }
}

fn stop_child(child: &mut Child, signal: &str) {
    #[cfg(unix)]
    if !signal_group(child.id(), signal) {
        let _ = child.kill();
    }
    #[cfg(windows)]
    {
        let _ = signal;
        let _ = child.start_kill();
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader},
        process::Stdio,
        time::Instant,
    };

    #[test]
    fn cancellation_stops_owned_descendants_and_leaves_other_jobs_running() {
        let mut other_command = crate::platform::powershell().unwrap();
        other_command.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Sleep 60",
        ]);
        let other = OwnedChild::start(&mut other_command, Arc::new(AtomicUsize::new(0))).unwrap();
        let cancelled = Arc::new(AtomicUsize::new(0));
        let mut command = crate::platform::powershell().unwrap();
        command.args(["-NoProfile", "-NonInteractive", "-Command",
            "$p = Start-Process (Join-Path $PSHOME powershell.exe) -ArgumentList '-NoProfile -NonInteractive -Command Start-Sleep 60' -PassThru; Write-Output $p.Id; Start-Sleep 60"])
            .stdout(Stdio::piped());
        let child = OwnedChild::start(&mut command, Arc::clone(&cancelled)).unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let stdout = child.take_stdout().unwrap();
        let reader = thread::spawn(move || {
            let mut line = String::new();
            BufReader::new(stdout).read_line(&mut line).unwrap();
            send.send(line).unwrap();
        });
        let pid: u32 = receive
            .recv_timeout(Duration::from_secs(20))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        reader.join().unwrap();
        cancelled.store(1, Ordering::Relaxed);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(!status.success());
                break;
            }
            assert!(Instant::now() < deadline, "owned job did not stop");
            thread::sleep(Duration::from_millis(50));
        }
        let status = crate::platform::powershell().unwrap().args(["-NoProfile", "-NonInteractive", "-Command",
            "if (Get-Process -Id $env:OPSFORGE_TEST_PID -ErrorAction SilentlyContinue) { exit 1 }"])
            .env("OPSFORGE_TEST_PID", pid.to_string()).status().unwrap();
        assert!(status.success(), "owned descendant survived cancellation");
        assert!(other.try_wait().unwrap().is_none());
    }
}
