// SPDX-License-Identifier: BSD-3-Clause-LBNL
use std::sync::mpsc;
use std::sync::Arc;
use std::time::SystemTime;

use chrono::Utc;

pub enum MetaEventType {
    Send {
        tick: u64,
        part: u32,
        total_parts: u32,
    },
    Recv {
        tick: u64,
        part: u32,
        total_parts: u32,
    },
    Reassemble {
        tick: u64,
    },
    Complete {
        tick: u64,
    },
    SendControl {
        control_signal: f64,
    },
}

pub struct MetaEvent {
    pub timestamp: SystemTime,
    pub from: Arc<str>,
    pub event: MetaEventType,
}

pub struct MetaEventManager {
    pub enabled: bool,
    sender: mpsc::Sender<MetaEvent>,
}

impl MetaEventManager {
    pub fn new(enabled: bool) -> (Self, mpsc::Receiver<MetaEvent>) {
        let (sender, receiver) = mpsc::channel();
        (Self { enabled, sender }, receiver)
    }

    // Creates a lower-level context for a specific thread or component.
    pub fn create_context(&self, name: impl Into<Arc<str>>) -> Option<MetaEventContext> {
        if self.enabled {
            Some(MetaEventContext {
                name: name.into(),
                sender: self.sender.clone(),
            })
        } else {
            None
        }
    }
}

// Lower-level context specific to each thread.
#[derive(Clone)]
pub struct MetaEventContext {
    name: Arc<str>,
    sender: mpsc::Sender<MetaEvent>,
}

impl MetaEventContext {
    // Emit an event through the shared sender.
    pub fn emit(&self, event: MetaEventType) {
        let meta_event = MetaEvent {
            timestamp: SystemTime::now(),
            from: Arc::clone(&self.name),
            event,
        };
        self.sender.send(meta_event).unwrap();
    }
}

// Function to format an event into a string.
fn format_event(event: &MetaEvent) -> String {
    let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let event_type = match &event.event {
        MetaEventType::Send {
            tick,
            part,
            total_parts,
        } => {
            format!("{tick}:{part}/{total_parts},{},sent", event.from)
        }
        MetaEventType::Recv {
            tick,
            part,
            total_parts,
        } => {
            format!("{tick}:{part}/{total_parts},{},recv", event.from)
        }
        MetaEventType::Reassemble { tick } => {
            format!("{tick},{},reassembled", event.from)
        }
        MetaEventType::Complete { tick } => {
            format!("{tick},{},processed", event.from)
        }
        MetaEventType::SendControl { control_signal } => {
            format!("{control_signal},{},control", event.from)
        }
    };
    format!("{timestamp},{}\n", event_type)
}

pub fn write_events_to_csv(
    receiver: mpsc::Receiver<MetaEvent>,
    csv_path: &str,
) -> std::io::Result<()> {
    use std::fs::File;
    use std::io::Write;

    let mut file = File::create(csv_path)?;

    for event in receiver {
        let formatted_event = format_event(&event);
        file.write_all(formatted_event.as_bytes())?;
    }

    Ok(())
}
