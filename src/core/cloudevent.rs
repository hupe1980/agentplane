//! The [CloudEvents] 1.0 envelope, in both directions.
//!
//! # Why the envelope is a type and not two hand-written maps
//!
//! This plane **emits** `CloudEvents` — [`RunCompleted`](crate::push::RunCompleted)
//! posts one per sealed run — and it **accepts** them, because the counterparty
//! that wakes a run is an event bus and not a caller who read our JSON shape.
//! Written twice, those two ends drift: the emitter sorts attributes one way,
//! the reader accepts an attribute the emitter never sets, and the media type
//! that tells a receiver which of the two it is holding is a string literal in
//! whichever file happened to need it. One type states the required attributes,
//! the media type and the uniqueness pair once, and both directions are that
//! statement.
//!
//! # What this deliberately does not accept
//!
//! * **Any `specversion` but `1.0`.** A plane that guessed at an envelope it
//!   does not know would deliver a payload it has not understood.
//! * **`data_base64`.** The JSON event format allows binary data; a run's
//!   payload is a JSON value, and decoding one to hand a run bytes it cannot
//!   address is a conversion nobody asked for.
//! * **A non-JSON `datacontenttype` in binary mode.** The body becomes an
//!   event payload, and payloads here are JSON values. Refusing is a clear
//!   answer; wrapping arbitrary bytes in a JSON string is a silent retype.
//!
//! # The two attributes that do not mean what a producer intends
//!
//! `time` is parsed, carried and **never** used as the runtime's instant: time
//! in a run comes from journaled `clock.now` effects precisely so replay sees
//! the instant the run saw, and adopting a counterparty's clock would make
//! replay depend on it.
//!
//! `source` is provenance, not authority — anyone may write any string. It is
//! half of the uniqueness pair ([`origin_id`](`CloudEvent`::origin_id)) and a
//! label a policy may reason about once a transport has authenticated the
//! sender by other means. It is never the sender's identity on its own.
//!
//! [CloudEvents]: https://github.com/cloudevents/spec/blob/main/cloudevents/spec.md

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize, ser::SerializeMap};
use serde_json::Value;

use crate::core::{InboundEvent, Timestamp};

/// The only envelope version this plane reads or writes.
pub const SPEC_VERSION: &str = "1.0";

/// The media type of a structured-mode `CloudEvent`, as the HTTP binding
/// requires it on `Content-Type`.
///
/// A receiver routes on this. Posting a `CloudEvent` under any other media type
/// produces a body that is a valid event and reaches nothing that parses one.
pub const CONTENT_TYPE: &str = "application/cloudevents+json; charset=UTF-8";

/// The HTTP binding's header prefix for binary-mode attributes.
pub const HEADER_PREFIX: &str = "ce-";

/// Why an envelope was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CloudEventError {
    #[error("not a JSON object: {0}")]
    Malformed(String),
    #[error(
        "specversion '{0}' is not '{expected}' — this plane does not guess at an \
         envelope it has not been written against",
        expected = SPEC_VERSION
    )]
    UnknownSpecVersion(String),
    #[error("CloudEvents requires a non-empty '{0}'")]
    MissingAttribute(&'static str),
    #[error(
        "extension attribute '{0}' is not a CloudEvents attribute name: names are \
         lowercase letters and digits, so an event that travels over a binding \
         with case-insensitive keys cannot arrive as a different event"
    )]
    BadExtensionName(String),
    #[error("'time' is not an RFC 3339 timestamp: {0}")]
    BadTime(String),
    #[error(
        "'data_base64' carries bytes, and an event payload here is a JSON value — \
         send the data as JSON or address the bytes through a blob reference"
    )]
    BinaryData,
    #[error(
        "datacontenttype '{0}' is not JSON, and the body of a binary-mode event \
         becomes a JSON payload — wrapping other bytes in a string would retype \
         them silently"
    )]
    UnsupportedDataContentType(String),
    #[error("a percent-encoded header value is not valid UTF-8: {0}")]
    BadHeaderEncoding(String),
}

/// One `CloudEvents` 1.0 message.
///
/// Constructed by [`new`](Self::new) for emission and by
/// [`from_json`](Self::from_json) / [`from_http`](Self::from_http) for
/// ingestion; both paths run the same checks, so an event this plane emits is
/// one it would accept.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(try_from = "WireCloudEvent")]
pub struct CloudEvent {
    id: String,
    source: String,
    event_type: String,
    subject: Option<String>,
    time: Option<Timestamp>,
    datacontenttype: Option<String>,
    dataschema: Option<String>,
    extensions: BTreeMap<String, Value>,
    data: Option<Value>,
}

impl CloudEvent {
    /// An event with the three attributes `CloudEvents` requires.
    ///
    /// # Errors
    ///
    /// [`CloudEventError::MissingAttribute`] if any of them is empty. The spec
    /// says MUST be non-empty for all three, and an event missing one is one a
    /// conformant receiver refuses — better refused where it is written.
    pub fn new(
        source: impl Into<String>,
        id: impl Into<String>,
        event_type: impl Into<String>,
    ) -> Result<Self, CloudEventError> {
        let event = Self {
            id: id.into(),
            source: source.into(),
            event_type: event_type.into(),
            subject: None,
            time: None,
            datacontenttype: None,
            dataschema: None,
            extensions: BTreeMap::new(),
            data: None,
        };
        event.checked()
    }

    fn checked(self) -> Result<Self, CloudEventError> {
        if self.id.is_empty() {
            return Err(CloudEventError::MissingAttribute("id"));
        }
        if self.source.is_empty() {
            return Err(CloudEventError::MissingAttribute("source"));
        }
        if self.event_type.is_empty() {
            return Err(CloudEventError::MissingAttribute("type"));
        }
        for name in self.extensions.keys() {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            {
                return Err(CloudEventError::BadExtensionName(name.clone()));
            }
        }
        Ok(self)
    }

    /// The JSON `data`, which becomes an [`InboundEvent`]'s payload.
    #[must_use]
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self.datacontenttype = Some("application/json".to_owned());
        self
    }

    /// What this event is *about* within the producer — a run, an order, a
    /// meter. Distinct from `source`, which names the producer itself.
    #[must_use]
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// An extension attribute.
    ///
    /// # Errors
    ///
    /// [`CloudEventError::BadExtensionName`] unless the name is lowercase
    /// letters and digits.
    pub fn with_extension(
        mut self,
        name: impl Into<String>,
        value: Value,
    ) -> Result<Self, CloudEventError> {
        self.extensions.insert(name.into(), value);
        self.checked()
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The `type` attribute. Spelled `event_type` because `type` is a keyword.
    #[must_use]
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    /// The producer's clock, if it set one. **Never** the runtime's instant.
    #[must_use]
    pub const fn time(&self) -> Option<Timestamp> {
        self.time
    }

    #[must_use]
    pub fn data(&self) -> Option<&Value> {
        self.data.as_ref()
    }

    /// One extension attribute, if the producer set it.
    #[must_use]
    pub fn extension(&self, name: &str) -> Option<&Value> {
        self.extensions.get(name)
    }

    /// The pair `CloudEvents` defines uniqueness by, as one string.
    ///
    /// `id` alone is unique only within one producer: two counterparties
    /// numbering their messages from one collide, and the collision is silent
    /// because the second message looks exactly like a retry of the first. The
    /// separator is a unit separator (U+001F) so that no `source`/`id` pair a
    /// producer can write spells another — the same construction, and the same
    /// reason, as [`InboundEvent::dedup_key`].
    #[must_use]
    pub fn origin_id(&self) -> String {
        format!("{}\u{1f}{}", self.source, self.id)
    }

    /// This event as something a run can wait for.
    ///
    /// `source` is **not** the event's own: it is whoever the transport
    /// authenticated. A self-asserted source would make the deduplication
    /// identity a pair the sender controls both halves of, so one counterparty
    /// could deduplicate against another's messages by naming them. The
    /// producer's claim survives inside the id, as
    /// [`origin_id`](Self::origin_id) — which keeps a relay carrying many
    /// producers' events from collapsing two of them into one.
    #[must_use]
    pub fn into_inbound(self, transport_source: impl Into<String>) -> InboundEvent {
        InboundEvent::new(
            transport_source,
            self.origin_id(),
            self.event_type,
            self.data.unwrap_or(Value::Null),
        )
    }

    /// Parse a structured-mode body.
    ///
    /// # Errors
    ///
    /// [`CloudEventError`] when the body is not a JSON object, names another
    /// `specversion`, is missing a required attribute, or carries data this
    /// plane does not accept.
    pub fn from_json(body: &[u8]) -> Result<Self, CloudEventError> {
        let wire: WireCloudEvent =
            serde_json::from_slice(body).map_err(|e| CloudEventError::Malformed(e.to_string()))?;
        Self::try_from(wire)
    }

    /// Parse an HTTP message in whichever content mode it used.
    ///
    /// Structured mode is chosen by the `Content-Type`; anything else is read
    /// as binary mode, where the attributes are `ce-`-prefixed headers and the
    /// body is the data. `headers` is any iterator of `(name, value)`; names
    /// are compared case-insensitively, as HTTP requires.
    ///
    /// # Errors
    ///
    /// [`CloudEventError`] for the reasons [`from_json`](Self::from_json)
    /// gives, plus a percent-encoded header value that is not UTF-8.
    pub fn from_http<'a, I>(headers: I, body: &[u8]) -> Result<Self, CloudEventError>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut content_type = None;
        let mut attributes: BTreeMap<String, String> = BTreeMap::new();
        for (name, value) in headers {
            let name = name.to_ascii_lowercase();
            if name == "content-type" {
                content_type = Some(value.to_owned());
            } else if let Some(attribute) = name.strip_prefix(HEADER_PREFIX) {
                attributes.insert(attribute.to_owned(), percent_decode(value)?);
            }
        }
        if content_type
            .as_deref()
            .is_some_and(|value| media_type_of(value) == "application/cloudevents+json")
        {
            return Self::from_json(body);
        }
        Self::from_binary(&attributes, content_type.as_deref(), body)
    }

    fn from_binary(
        attributes: &BTreeMap<String, String>,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Result<Self, CloudEventError> {
        let take = |name: &str| attributes.get(name).cloned();
        let specversion = take("specversion").unwrap_or_default();
        if specversion != SPEC_VERSION {
            return Err(CloudEventError::UnknownSpecVersion(specversion));
        }
        let data = if body.is_empty() {
            None
        } else {
            // `datacontenttype` rides on `Content-Type` in binary mode, and a
            // body that is not JSON cannot become a JSON payload without being
            // retyped.
            let media = content_type.map_or("application/json", media_type_of);
            if !is_json_media_type(media) {
                return Err(CloudEventError::UnsupportedDataContentType(
                    media.to_owned(),
                ));
            }
            Some(
                serde_json::from_slice(body)
                    .map_err(|e| CloudEventError::Malformed(e.to_string()))?,
            )
        };
        let time = take("time").map(|raw| parse_time(&raw)).transpose()?;
        let known = [
            "specversion",
            "id",
            "source",
            "type",
            "subject",
            "time",
            "dataschema",
            // The HTTP binding forbids it as a header: the media type carries
            // it. Ignored rather than promoted to an extension, which is where
            // it would otherwise land and where nothing reads it.
            "datacontenttype",
        ];
        let extensions = attributes
            .iter()
            .filter(|(name, _)| !known.contains(&name.as_str()))
            .map(|(name, value)| (name.clone(), Value::String(value.clone())))
            .collect();
        Self {
            id: take("id").unwrap_or_default(),
            source: take("source").unwrap_or_default(),
            event_type: take("type").unwrap_or_default(),
            subject: take("subject"),
            time,
            datacontenttype: content_type.map(|value| media_type_of(value).to_owned()),
            dataschema: take("dataschema"),
            extensions,
            data,
        }
        .checked()
    }

    /// The structured-mode body, with sorted keys.
    ///
    /// Through the canonical writer for the reason [`canon`](crate::core::canon)
    /// gives: a body that is signed, or that a receiver verifies by
    /// re-serializing what it parsed, needs bytes that are a function of the
    /// event rather than of the order it was built in.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::core::canon::value_bytes(&self.to_value())
    }

    /// The structured-mode JSON, attributes flat beside `data`.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut map = serde_json::Map::new();
        map.insert("specversion".to_owned(), Value::String(SPEC_VERSION.into()));
        map.insert("id".to_owned(), Value::String(self.id.clone()));
        map.insert("source".to_owned(), Value::String(self.source.clone()));
        map.insert("type".to_owned(), Value::String(self.event_type.clone()));
        for (name, value) in [
            ("subject", self.subject.as_ref()),
            ("datacontenttype", self.datacontenttype.as_ref()),
            ("dataschema", self.dataschema.as_ref()),
        ] {
            if let Some(value) = value {
                map.insert(name.to_owned(), Value::String(value.clone()));
            }
        }
        if let Some(time) = self.time {
            map.insert(
                "time".to_owned(),
                Value::String(crate::core::format_timestamp(time)),
            );
        }
        for (name, value) in &self.extensions {
            map.insert(name.clone(), value.clone());
        }
        if let Some(data) = &self.data {
            map.insert("data".to_owned(), data.clone());
        }
        Value::Object(map)
    }
}

impl Serialize for CloudEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = self.to_value();
        let object = value.as_object().expect("to_value builds an object");
        let mut map = serializer.serialize_map(Some(object.len()))?;
        for (key, value) in object {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

/// The wire form, carrying no invariant.
///
/// Deserializing is a constructor: every check [`CloudEvent::new`] makes has to
/// run on the serde path too, or the guarded shape is the one nobody uses —
/// events arrive over a bus, not through a builder.
#[derive(Deserialize)]
struct WireCloudEvent {
    specversion: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    source: String,
    #[serde(default, rename = "type")]
    event_type: String,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    time: Option<String>,
    #[serde(default)]
    datacontenttype: Option<String>,
    #[serde(default)]
    dataschema: Option<String>,
    #[serde(default)]
    data: Option<Value>,
    #[serde(default)]
    data_base64: Option<String>,
    #[serde(flatten)]
    extensions: BTreeMap<String, Value>,
}

impl TryFrom<WireCloudEvent> for CloudEvent {
    type Error = CloudEventError;

    fn try_from(wire: WireCloudEvent) -> Result<Self, Self::Error> {
        if wire.specversion != SPEC_VERSION {
            return Err(CloudEventError::UnknownSpecVersion(wire.specversion));
        }
        if wire.data_base64.is_some() {
            return Err(CloudEventError::BinaryData);
        }
        let time = wire.time.map(|raw| parse_time(&raw)).transpose()?;
        Self {
            id: wire.id,
            source: wire.source,
            event_type: wire.event_type,
            subject: wire.subject,
            time,
            datacontenttype: wire.datacontenttype,
            dataschema: wire.dataschema,
            extensions: wire.extensions,
            data: wire.data,
        }
        .checked()
    }
}

fn parse_time(raw: &str) -> Result<Timestamp, CloudEventError> {
    Timestamp::parse(raw, &time::format_description::well_known::Rfc3339)
        .map_err(|error| CloudEventError::BadTime(format!("{raw}: {error}")))
}

/// The media type without its parameters, lowercased.
fn media_type_of(header: &str) -> &str {
    header
        .split(';')
        .next()
        .unwrap_or(header)
        .trim()
        .trim_end_matches('/')
}

/// Whether a media type carries JSON, including the `+json` structured suffix
/// that `application/a2a+json` and `application/cloudevents+json` both use.
fn is_json_media_type(media: &str) -> bool {
    media.eq_ignore_ascii_case("application/json")
        || media.eq_ignore_ascii_case("text/json")
        || media.to_ascii_lowercase().ends_with("+json")
}

/// Decode the HTTP binding's percent-encoding of a header value.
///
/// The binding percent-encodes the characters a header cannot carry — anything
/// outside printable US-ASCII, plus `%` itself. A lone `%` that does not begin
/// a valid escape is kept verbatim rather than refused: it is what a producer
/// that never encoded anything sends, and refusing would reject events that no
/// binding rule made illegal.
fn percent_decode(value: &str) -> Result<String, CloudEventError> {
    if !value.contains('%') {
        return Ok(value.to_owned());
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3])
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok());
            if let Some(byte) = hex {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(out).map_err(|error| CloudEventError::BadHeaderEncoding(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn structured(body: &serde_json::Value) -> Result<CloudEvent, CloudEventError> {
        CloudEvent::from_json(body.to_string().as_bytes())
    }

    /// The ordinary structured-mode message, with the attributes flat beside
    /// the data as the JSON event format puts them.
    #[test]
    fn a_structured_event_parses_into_its_attributes() {
        let event = structured(&json!({
            "specversion": "1.0",
            "type": "de.messwert.reading.direct.stored",
            "source": "/edmd",
            "id": "1",
            "subject": "malo/42",
            "time": "2026-08-19T09:00:00Z",
            "datacontenttype": "application/json",
            "tenantid": "acme",
            "data": {"malo": "42"},
        }))
        .expect("a conformant event");

        assert_eq!(event.event_type(), "de.messwert.reading.direct.stored");
        assert_eq!(event.source(), "/edmd");
        assert_eq!(event.id(), "1");
        assert_eq!(event.subject(), Some("malo/42"));
        assert_eq!(event.data(), Some(&json!({"malo": "42"})));
        assert_eq!(
            event.extension("tenantid"),
            Some(&json!("acme")),
            "an unknown attribute is an extension, not a discard: a deployment \
             binds tenants on one"
        );
        assert!(
            event.time().is_some(),
            "the producer's clock was dropped rather than carried"
        );
    }

    /// The identity a duplicate is recognised by is the **pair**.
    ///
    /// `id` alone is unique only within one producer. Two counterparties
    /// numbering their messages from one collide, and the collision is silent:
    /// the second message looks exactly like a retry of the first and is
    /// dropped as one.
    #[test]
    fn two_producers_numbering_from_one_are_not_the_same_event() {
        let first = CloudEvent::new("/edmd", "1", "reading.stored").unwrap();
        let second = CloudEvent::new("/erp", "1", "reading.stored").unwrap();
        assert_ne!(first.origin_id(), second.origin_id());

        // And no pair a producer can write spells another's, because the
        // separator is not a character a URI or an id may contain.
        let sneaky = CloudEvent::new("/edmd\u{1f}1", "", "x");
        assert!(
            sneaky.is_err(),
            "an empty id is not refused, so a source can be padded to spell \
             another pair"
        );
    }

    /// Binary content mode: attributes in `ce-` headers, data in the body.
    #[test]
    fn a_binary_mode_event_parses_from_its_headers() {
        let event = CloudEvent::from_http(
            [
                ("Content-Type", "application/json"),
                ("ce-specversion", "1.0"),
                ("ce-id", "42"),
                ("ce-source", "/edmd"),
                ("ce-type", "reading.stored"),
                ("ce-tenantid", "acme"),
            ],
            br#"{"malo":"7"}"#,
        )
        .expect("a conformant binary-mode event");

        assert_eq!(event.id(), "42");
        assert_eq!(event.event_type(), "reading.stored");
        assert_eq!(event.data(), Some(&json!({"malo": "7"})));
        assert_eq!(event.extension("tenantid"), Some(&json!("acme")));
    }

    /// A structured body wins whatever the `ce-` headers say, because the
    /// media type is what the binding dispatches on.
    #[test]
    fn the_content_type_decides_which_mode_a_message_is_in() {
        let event = CloudEvent::from_http(
            [
                (
                    "content-type",
                    "application/cloudevents+json; charset=UTF-8",
                ),
                ("ce-id", "from-the-headers"),
            ],
            br#"{"specversion":"1.0","id":"from-the-body","source":"/x","type":"t"}"#,
        )
        .expect("a structured message");
        assert_eq!(event.id(), "from-the-body");
    }

    /// Header values are percent-encoded by the binding when they carry
    /// anything a header cannot.
    #[test]
    fn a_percent_encoded_header_value_is_decoded() {
        let event = CloudEvent::from_http(
            [
                ("ce-specversion", "1.0"),
                ("ce-id", "1"),
                ("ce-source", "/z%C3%A4hler"),
                ("ce-type", "t"),
            ],
            b"",
        )
        .expect("a conformant event");
        assert_eq!(event.source(), "/zähler");
        assert_eq!(event.data(), None, "an empty body is no data, not null");
    }

    /// Every refusal, stated once, because each of them is a message this
    /// plane would otherwise pass on without having understood it.
    #[test]
    fn what_is_refused_and_why() {
        assert!(matches!(
            structured(&json!({"specversion": "0.3", "id": "1", "source": "/x", "type": "t"})),
            Err(CloudEventError::UnknownSpecVersion(_)),
        ));
        assert!(matches!(
            structured(&json!({"specversion": "1.0", "id": "", "source": "/x", "type": "t"})),
            Err(CloudEventError::MissingAttribute("id"))
        ));
        assert!(matches!(
            structured(&json!({"specversion": "1.0", "id": "1", "source": "", "type": "t"})),
            Err(CloudEventError::MissingAttribute("source"))
        ));
        assert!(matches!(
            structured(&json!({"specversion": "1.0", "id": "1", "source": "/x", "type": ""})),
            Err(CloudEventError::MissingAttribute("type"))
        ));
        assert!(
            matches!(
                structured(&json!({
                    "specversion": "1.0", "id": "1", "source": "/x", "type": "t",
                    "data_base64": "aGk=",
                })),
                Err(CloudEventError::BinaryData)
            ),
            "bytes were decoded into a payload a run cannot address"
        );
        assert!(
            matches!(
                structured(&json!({
                    "specversion": "1.0", "id": "1", "source": "/x", "type": "t",
                    "tenantId": "acme",
                })),
                Err(CloudEventError::BadExtensionName(_))
            ),
            "an extension name that is not lowercase alphanumeric arrives as a \
             different name over a binding with case-insensitive keys"
        );
        assert!(matches!(
            structured(&json!({
                "specversion": "1.0", "id": "1", "source": "/x", "type": "t",
                "time": "yesterday",
            })),
            Err(CloudEventError::BadTime(_))
        ));
        assert!(
            matches!(
                CloudEvent::from_http(
                    [
                        ("content-type", "application/octet-stream"),
                        ("ce-specversion", "1.0"),
                        ("ce-id", "1"),
                        ("ce-source", "/x"),
                        ("ce-type", "t"),
                    ],
                    b"\x00\x01",
                ),
                Err(CloudEventError::UnsupportedDataContentType(_))
            ),
            "arbitrary bytes were retyped as a JSON payload"
        );
    }

    /// What this plane emits is what it would accept.
    ///
    /// The two directions are one type precisely so they cannot drift; this is
    /// the assertion that says so.
    #[test]
    fn an_emitted_event_parses_back_to_itself() {
        let event = CloudEvent::new("urn:mako:agentd", "run-1", "io.agentplane.run.completed")
            .expect("the three required attributes")
            .with_subject("run-1")
            .with_extension("tenantid", json!("acme"))
            .expect("a conformant extension name")
            .with_data(json!({"outcome": "success"}));

        let parsed = CloudEvent::from_json(&event.to_bytes()).expect("our own bytes");
        assert_eq!(parsed, event);
        assert_eq!(
            parsed.to_bytes(),
            event.to_bytes(),
            "the encoding is not a function of the event, so a signature over \
             it cannot be reproduced"
        );
    }

    /// The transport's identity is the source of the buffered event, and the
    /// producer's claim survives inside the id.
    #[test]
    fn an_inbound_event_keeps_the_producers_pair_without_trusting_it() {
        let event = CloudEvent::new("/edmd", "7", "reading.stored")
            .unwrap()
            .with_data(json!({"malo": "42"}));
        let inbound = event.clone().into_inbound("peer:gateway");

        assert_eq!(
            inbound.source, "peer:gateway",
            "a self-asserted source lets a caller pick the namespace it \
             deduplicates in"
        );
        assert_eq!(inbound.id, event.origin_id());
        assert_eq!(inbound.kind, "reading.stored");
        assert_eq!(inbound.payload, json!({"malo": "42"}));
    }
}
