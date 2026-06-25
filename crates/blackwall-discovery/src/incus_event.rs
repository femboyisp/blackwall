//! Parse Incus lifecycle event-stream lines.

use crate::error::DiscoveryError;

/// The kind of instance lifecycle change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceChange {
    /// The instance started.
    Started,
    /// The instance stopped.
    Stopped,
    /// The instance configuration was updated.
    Updated,
}

/// A parsed instance lifecycle event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleEvent {
    /// The instance name the event refers to.
    pub instance: String,
    /// What changed.
    pub change: InstanceChange,
}

/// Parse one event-stream line. Returns `Ok(None)` for non-instance-lifecycle
/// events, `Ok(Some(..))` for instance start/stop/update, `Err` on malformed JSON.
pub fn parse_event(line: &str) -> Result<Option<LifecycleEvent>, DiscoveryError> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(None);
    }
    let v: serde_json::Value =
        serde_json::from_str(line).map_err(|e| DiscoveryError::Parse(e.to_string()))?;
    if v["type"].as_str() != Some("lifecycle") {
        return Ok(None);
    }
    let action = v["metadata"]["action"].as_str().unwrap_or_default();
    let change = match action {
        "instance-started" => InstanceChange::Started,
        "instance-stopped" | "instance-shutdown" => InstanceChange::Stopped,
        "instance-updated" => InstanceChange::Updated,
        _ => return Ok(None),
    };
    // The source is like "/1.0/instances/web01".
    let source = v["metadata"]["source"].as_str().unwrap_or_default();
    let instance = source.rsplit('/').next().unwrap_or_default().to_owned();
    if instance.is_empty() {
        return Err(DiscoveryError::Parse(
            "lifecycle event missing instance".to_owned(),
        ));
    }
    Ok(Some(LifecycleEvent { instance, change }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_started_event() {
        let line = r#"{"type":"lifecycle","metadata":{"action":"instance-started","source":"/1.0/instances/web01"}}"#;
        let ev = parse_event(line).expect("ok").expect("some");
        assert_eq!(ev.instance, "web01");
        assert_eq!(ev.change, InstanceChange::Started);
    }

    #[test]
    fn ignores_non_lifecycle() {
        let line = r#"{"type":"logging","metadata":{}}"#;
        assert_eq!(parse_event(line).expect("ok"), None);
    }

    #[test]
    fn ignores_unrelated_action() {
        let line = r#"{"type":"lifecycle","metadata":{"action":"image-created","source":"/1.0/images/x"}}"#;
        assert_eq!(parse_event(line).expect("ok"), None);
    }

    #[test]
    fn malformed_json_errors() {
        assert!(parse_event("{not json").is_err());
    }

    #[test]
    fn shutdown_maps_to_stopped() {
        let line = r#"{"type":"lifecycle","metadata":{"action":"instance-shutdown","source":"/1.0/instances/db01"}}"#;
        let ev = parse_event(line).expect("ok").expect("some");
        assert_eq!(ev.instance, "db01");
        assert_eq!(ev.change, InstanceChange::Stopped);
    }

    #[test]
    fn empty_instance_errors() {
        // source ends with a slash -> trailing segment is empty
        let line = r#"{"type":"lifecycle","metadata":{"action":"instance-started","source":"/1.0/instances/"}}"#;
        assert!(parse_event(line).is_err());
    }
}
