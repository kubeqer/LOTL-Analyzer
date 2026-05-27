use crate::config::{CMDLINE_FIELDS, DROP_EVENT_IDS, SECRET_PATTERNS};
use crate::event::SysmonEvent;
use anyhow::Result;
use regex::Regex;

pub struct Sanitizer {
    compiled_patterns: Vec<(Regex, &'static str)>,
}

impl Sanitizer {
    pub fn new() -> Result<Self> {
        let compiled_patterns = compile_patterns()?;
        Ok(Self { compiled_patterns })
    }

    pub fn process(&self, mut event: SysmonEvent) -> Option<SysmonEvent> {
        if is_dropped(event.event_id) {
            return None;
        }
        self.redact_command_line_fields(&mut event);
        Some(event)
    }

    fn redact_command_line_fields(&self, event: &mut SysmonEvent) {
        for field_name in CMDLINE_FIELDS {
            if let Some(value) = event.data.get_mut(*field_name) {
                *value = self.redact(value);
            }
        }
    }

    fn redact(&self, input: &str) -> String {
        let mut output = input.to_string();
        for (pattern, replacement) in &self.compiled_patterns {
            output = pattern.replace_all(&output, *replacement).into_owned();
        }
        output
    }
}

fn compile_patterns() -> Result<Vec<(Regex, &'static str)>> {
    let mut compiled = Vec::with_capacity(SECRET_PATTERNS.len());
    for (pattern, replacement) in SECRET_PATTERNS {
        compiled.push((Regex::new(pattern)?, *replacement));
    }
    Ok(compiled)
}

fn is_dropped(event_id: u32) -> bool {
    DROP_EVENT_IDS.contains(&event_id)
}
