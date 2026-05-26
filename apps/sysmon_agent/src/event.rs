use anyhow::{anyhow, Result};
use quick_xml::events::{BytesCData, BytesEnd, BytesStart, BytesText, Event as XmlEvent};
use quick_xml::Reader;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SysmonEvent {
    pub record_id: u64,
    pub event_id: u32,
    pub level: u32,
    pub provider: String,
    pub channel: String,
    pub computer: String,
    pub time_created: String,
    #[serde(default)]
    pub data: BTreeMap<String, String>,
}

#[derive(Default)]
struct ParserState {
    current_data_name: Option<String>,
    text_buffer: String,
}

pub fn parse_event_xml(xml: &str) -> Result<SysmonEvent> {
    let mut reader = Reader::from_str(xml);
    let mut event = SysmonEvent::default();
    let mut state = ParserState::default();
    let mut reader_buffer = Vec::new();

    loop {
        match reader.read_event_into(&mut reader_buffer) {
            Ok(XmlEvent::Start(element)) | Ok(XmlEvent::Empty(element)) => {
                handle_start_element(&element, &mut event, &mut state)?;
            }
            Ok(XmlEvent::Text(text)) => {
                append_text(&text, &mut state)?;
            }
            Ok(XmlEvent::CData(cdata)) => {
                append_cdata(&cdata, &mut state)?;
            }
            Ok(XmlEvent::End(element)) => {
                handle_end_element(&element, &mut event, &mut state)?;
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                return Err(anyhow!(
                    "xml parse error at byte {}: {}",
                    reader.buffer_position(),
                    error
                ));
            }
        }
        reader_buffer.clear();
    }

    if event.record_id == 0 && event.event_id == 0 {
        return Err(anyhow!("xml did not contain a Sysmon event"));
    }
    Ok(event)
}

fn handle_start_element(
    element: &BytesStart<'_>,
    event: &mut SysmonEvent,
    state: &mut ParserState,
) -> Result<()> {
    let local_name = element_local_name(element.local_name().as_ref())?;
    match local_name.as_str() {
        "TimeCreated" => {
            if let Some(value) = read_attribute(element, b"SystemTime")? {
                event.time_created = value;
            }
        }
        "Provider" => {
            if let Some(value) = read_attribute(element, b"Name")? {
                event.provider = value;
            }
        }
        "Data" => {
            state.current_data_name = read_attribute(element, b"Name")?;
        }
        _ => {}
    }
    state.text_buffer.clear();
    Ok(())
}

fn handle_end_element(
    element: &BytesEnd<'_>,
    event: &mut SysmonEvent,
    state: &mut ParserState,
) -> Result<()> {
    let local_name = element_local_name(element.local_name().as_ref())?;
    let trimmed_text = state.text_buffer.trim();
    match local_name.as_str() {
        "EventID" => event.event_id = trimmed_text.parse().unwrap_or(0),
        "EventRecordID" => event.record_id = trimmed_text.parse().unwrap_or(0),
        "Level" => event.level = trimmed_text.parse().unwrap_or(0),
        "Channel" => event.channel = trimmed_text.to_string(),
        "Computer" => event.computer = trimmed_text.to_string(),
        "Data" => {
            if let Some(key) = state.current_data_name.take() {
                event.data.insert(key, trimmed_text.to_string());
            }
        }
        _ => {}
    }
    state.text_buffer.clear();
    Ok(())
}

fn append_text(text: &BytesText<'_>, state: &mut ParserState) -> Result<()> {
    let decoded = text
        .unescape()
        .map_err(|error| anyhow!("text decode: {error}"))?;
    state.text_buffer.push_str(decoded.as_ref());
    Ok(())
}

fn append_cdata(cdata: &BytesCData<'_>, state: &mut ParserState) -> Result<()> {
    let decoded =
        std::str::from_utf8(cdata.as_ref()).map_err(|error| anyhow!("cdata decode: {error}"))?;
    state.text_buffer.push_str(decoded);
    Ok(())
}

fn read_attribute(element: &BytesStart<'_>, attribute_key: &[u8]) -> Result<Option<String>> {
    for attribute in element.attributes().flatten() {
        if attribute.key.as_ref() == attribute_key {
            let value = attribute
                .unescape_value()
                .map_err(|error| anyhow!("attribute decode: {error}"))?
                .into_owned();
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn element_local_name(name_bytes: &[u8]) -> Result<String> {
    std::str::from_utf8(name_bytes)
        .map(|name| name.to_string())
        .map_err(|error| anyhow!("invalid utf-8 in element name: {error}"))
}
