use serde::{Deserialize, Serialize};
use std::{
    fmt,
    path::PathBuf,
    str::FromStr,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CaptureDuration {
    seconds: u64,
    label: String,
}

impl<'de> Deserialize<'de> for CaptureDuration {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct LegacyDuration {
            seconds: u64,
            label: String,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Input {
            Label(String),
            Legacy(LegacyDuration),
        }
        let input = Input::deserialize(deserializer)?;
        let (label, seconds) = match input {
            Input::Label(label) => (label, None),
            Input::Legacy(value) => (value.label, Some(value.seconds)),
        };
        let duration: Self = label.parse().map_err(serde::de::Error::custom)?;
        if seconds.is_some_and(|seconds| seconds != duration.seconds) {
            return Err(serde::de::Error::custom(
                "capture seconds do not match the label",
            ));
        }
        Ok(duration)
    }
}

impl CaptureDuration {
    #[must_use]
    pub fn seconds(&self) -> u64 {
        self.seconds
    }
}

impl From<CaptureDuration> for Duration {
    fn from(value: CaptureDuration) -> Self {
        Self::from_secs(value.seconds)
    }
}

impl fmt::Display for CaptureDuration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.label)
    }
}

impl FromStr for CaptureDuration {
    type Err = &'static str;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let unit_start = input
            .char_indices()
            .last()
            .map(|(index, _)| index)
            .ok_or("use 1s, 5m, 1h, or 1d")?;
        let (digits, unit) = input.split_at(unit_start);
        if digits.is_empty() || !digits.bytes().all(|digit| digit.is_ascii_digit()) {
            return Err("use a positive integer followed by s, m, h, or d");
        }
        let count: u64 = digits
            .parse()
            .map_err(|_| "capture duration is too large")?;
        if count == 0 {
            return Err("capture duration must be positive");
        }
        let multiplier = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 3_600,
            "d" => 86_400,
            _ => return Err("capture duration unit must be s, m, h, or d"),
        };
        let seconds = count
            .checked_mul(multiplier)
            .ok_or("capture duration is too large")?;
        Ok(Self {
            seconds,
            label: input.to_owned(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RunConfig {
    pub output_base: PathBuf,
    pub exfil: bool,
    pub timeline: bool,
    pub downloads: bool,
    pub deep_inventory: bool,
    pub live_capture: bool,
    pub capture_duration: CaptureDuration,
    pub imports: Vec<PathBuf>,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self::default_for(PathBuf::from("/var/lib/opsforge/cases"))
    }
}

impl RunConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.output_base.as_os_str().is_empty() {
            return Err("case output path must not be empty");
        }
        if self.imports.iter().any(|path| path.as_os_str().is_empty()) {
            return Err("import paths must not be empty");
        }
        if Instant::now()
            .checked_add(Duration::from_secs(self.capture_duration.seconds))
            .is_none()
        {
            return Err("capture duration exceeds the supported clock range");
        }
        Ok(())
    }

    #[must_use]
    pub fn default_for(output_base: PathBuf) -> Self {
        Self {
            output_base,
            exfil: true,
            timeline: true,
            downloads: true,
            deep_inventory: true,
            live_capture: true,
            capture_duration: CaptureDuration {
                seconds: 300,
                label: "5m".to_owned(),
            },
            imports: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CaptureDuration, RunConfig};
    use std::time::Duration;

    #[test]
    fn parses_requested_capture_units() {
        for (input, seconds) in [("1s", 1), ("5m", 300), ("2h", 7200), ("1d", 86400)] {
            assert_eq!(
                input.parse::<CaptureDuration>().map(Duration::from),
                Ok(Duration::from_secs(seconds))
            );
        }
    }

    #[test]
    fn rejects_missing_or_unbounded_capture_duration() {
        for input in [
            "",
            "0s",
            "1",
            "1w",
            "1.5h",
            "é",
            "1é",
            "999999999999999999999d",
        ] {
            assert!(input.parse::<CaptureDuration>().is_err(), "{input}");
        }
    }

    #[test]
    fn config_defaults_and_legacy_duration_round_trip() {
        let config: RunConfig =
            serde_json::from_str(r#"{"capture_duration":"2m","live_capture":false}"#)
                .expect("partial config");
        assert_eq!(config.capture_duration.seconds(), 120);
        assert!(!config.live_capture);
        assert!(config.exfil);
        config.validate().expect("valid config");
        let saved = serde_json::to_string(&config).expect("serialize");
        let restored: RunConfig = serde_json::from_str(&saved).expect("legacy object duration");
        assert_eq!(restored.capture_duration, config.capture_duration);
        for input in [
            r#"{"capture_duration":{"seconds":0,"label":"5m"}}"#,
            r#"{"capture_duration":"0s"}"#,
            r#"{"live_capure":false}"#,
        ] {
            assert!(serde_json::from_str::<RunConfig>(input).is_err(), "{input}");
        }
        let empty: RunConfig = serde_json::from_str(r#"{"output_base":""}"#).expect("decode empty");
        assert!(empty.validate().is_err());
    }
}
