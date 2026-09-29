//! Making what a reviewer cannot see visible, and flagging what they might
//! misread.
//!
//! Two different treatments, on purpose. A code point that renders as nothing
//! — a zero-width joiner, a Unicode tag, a variation selector — or that
//! reorders the text around it — a bidirectional override or isolate — hides
//! part of the value from the person reading it, so it is **escaped**: shown
//! as `\u{…}` in place. A word mixing scripts (a Cyrillic `а` inside a Latin
//! payee) is visible and may be legitimate, so it is **flagged** beside the
//! text and left alone. Nothing is refused: the plane holds no script policy,
//! and a real name in a non-Latin script is not an attack.
//!
//! The script table is coarse by design — the major alphabets a homoglyph is
//! drawn from, and "another script" for the rest. It answers *does this word
//! mix alphabets*, not Unicode's full confusable relation, which needs data
//! this crate does not carry.

/// Whether `c` renders as nothing, or changes how the text around it is
/// ordered.
///
/// The classes: C0 and C1 controls other than tab and the line breaks; the
/// bidirectional marks, embeddings, overrides and isolates; zero-width and
/// joiner controls, the word joiner and invisible operators, the byte-order
/// mark; the soft hyphen, the combining grapheme joiner and the filler
/// characters that render blank; variation selectors, which carry data
/// invisibly after any character; and the Unicode tag block.
#[must_use]
pub(crate) const fn is_hidden(c: char) -> bool {
    matches!(
        c as u32,
        0x00..=0x08
            | 0x0B..=0x0C
            | 0x0E..=0x1F
            | 0x7F..=0x9F
            | 0xAD
            | 0x034F
            | 0x061C
            | 0x115F..=0x1160
            | 0x17B4..=0x17B5
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x2069
            | 0x3164
            | 0xFE00..=0xFE0F
            | 0xFEFF
            | 0xFFA0
            | 0xE0000..=0xE007F
            | 0xE0100..=0xE01EF
    )
}

/// `text` with every hidden code point shown as `\u{…}`, and whether any was.
#[must_use]
pub(crate) fn escape(text: &str) -> (String, bool) {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(text.len());
    let mut escaped = false;
    for c in text.chars() {
        if is_hidden(c) {
            let _ = write!(out, "\\u{{{:04X}}}", c as u32);
            escaped = true;
        } else {
            out.push(c);
        }
    }
    (out, escaped)
}

/// The alphabet a letter belongs to, coarsely; `None` for anything that is not
/// a letter, which belongs to every script (digits, punctuation, spaces,
/// combining marks).
fn script(c: char) -> Option<&'static str> {
    if !c.is_alphabetic() {
        return None;
    }
    Some(match c as u32 {
        0x41..=0x5A
        | 0x61..=0x7A
        | 0xAA
        | 0xBA
        | 0xC0..=0xD6
        | 0xD8..=0xF6
        | 0xF8..=0x24F
        | 0x250..=0x2AF
        | 0x1E00..=0x1EFF
        | 0x2C60..=0x2C7F
        | 0xA720..=0xA7FF
        | 0xFF21..=0xFF3A
        | 0xFF41..=0xFF5A => "Latin",
        0x300..=0x36F => return None,
        0x370..=0x3FF | 0x1F00..=0x1FFF => "Greek",
        0x400..=0x52F | 0x1C80..=0x1C8F | 0x2DE0..=0x2DFF | 0xA640..=0xA69F => "Cyrillic",
        0x530..=0x58F => "Armenian",
        0x590..=0x5FF => "Hebrew",
        0x600..=0x6FF | 0x750..=0x77F | 0x8A0..=0x8FF | 0xFB50..=0xFDFF | 0xFE70..=0xFEFC => {
            "Arabic"
        }
        0x10A0..=0x10FF => "Georgian",
        0x13A0..=0x13FF => "Cherokee",
        // Han, kana and Hangul are written together in Japanese and Korean,
        // so they count as one script here: flagging `東京タワー` would be
        // noise, and the homoglyph attacks this exists for are alphabetic.
        0x3040..=0x30FF
        | 0x31F0..=0x31FF
        | 0x3400..=0x4DBF
        | 0x4E00..=0x9FFF
        | 0xF900..=0xFAFF
        | 0x1100..=0x11FF
        | 0x3130..=0x318F
        | 0xAC00..=0xD7AF => "CJK",
        _ => "another script",
    })
}

/// The scripts a word mixes, when it mixes more than one.
#[must_use]
pub(crate) fn mixed_scripts(word: &str) -> Option<Vec<&'static str>> {
    let mut seen: Vec<&'static str> = Vec::new();
    for s in word.chars().filter_map(script) {
        if !seen.contains(&s) {
            seen.push(s);
        }
    }
    (seen.len() > 1).then_some(seen)
}

#[cfg(test)]
mod tests {
    use super::{escape, mixed_scripts};

    #[test]
    fn hidden_code_points_are_shown_and_visible_ones_are_not_touched() {
        assert_eq!(escape("pay\u{202E}01"), ("pay\\u{202E}01".to_owned(), true));
        assert_eq!(
            escape("acct\u{E0041}\u{200B}"),
            ("acct\\u{E0041}\\u{200B}".to_owned(), true)
        );
        assert_eq!(escape("Zürich 東京\n"), ("Zürich 東京\n".to_owned(), false));
    }

    #[test]
    fn a_word_mixing_alphabets_is_named_and_one_script_is_not() {
        // A Cyrillic `а` (U+0430) inside a Latin word.
        assert_eq!(
            mixed_scripts("P\u{430}ypal"),
            Some(vec!["Latin", "Cyrillic"])
        );
        assert_eq!(mixed_scripts("Москва"), None);
        assert_eq!(mixed_scripts("東京タワー"), None);
        assert_eq!(mixed_scripts("AC-1234"), None);
    }
}
