#[must_use]
pub fn find_forward(
    needle: &[u8],
    haystack: &[u8],
    start: usize,
    case_sensitive: bool,
    wildcard: u8,
) -> Option<usize> {
    if needle.is_empty() {
        return Some(start.min(haystack.len()));
    }

    let remaining = haystack.len().checked_sub(start)?;
    if needle.len() > remaining {
        return None;
    }

    let last_start = haystack.len() - needle.len();
    (start..=last_start).find(|&index| {
        pattern_matches(
            needle,
            &haystack[index..index + needle.len()],
            case_sensitive,
            wildcard,
        )
    })
}

#[must_use]
pub fn find_quick(
    needle: &[u8],
    haystack: &[u8],
    start: usize,
    block_size: usize,
    case_sensitive: bool,
    wildcard: u8,
) -> Option<usize> {
    if needle.is_empty() {
        return Some(start.min(haystack.len()));
    }
    if block_size == 0 || needle.len() > haystack.len() {
        return None;
    }

    let rem = start % block_size;
    let mut index = if rem == 0 {
        start
    } else {
        start.saturating_add(block_size - rem)
    };

    while index + needle.len() <= haystack.len() {
        if pattern_matches(
            needle,
            &haystack[index..index + needle.len()],
            case_sensitive,
            wildcard,
        ) {
            return Some(index);
        }
        index = index.saturating_add(block_size);
    }

    None
}

#[must_use]
pub fn find_reverse(
    needle: &[u8],
    haystack: &[u8],
    case_sensitive: bool,
    wildcard: u8,
) -> Option<usize> {
    if needle.is_empty() {
        return Some(haystack.len());
    }
    if needle.len() > haystack.len() {
        return None;
    }

    (0..=haystack.len() - needle.len()).rev().find(|&index| {
        pattern_matches(
            needle,
            &haystack[index..index + needle.len()],
            case_sensitive,
            wildcard,
        )
    })
}

#[must_use]
pub fn pattern_matches(
    needle: &[u8],
    candidate: &[u8],
    case_sensitive: bool,
    wildcard: u8,
) -> bool {
    needle.len() == candidate.len()
        && needle
            .iter()
            .zip(candidate)
            .all(|(&expected, &actual)| byte_matches(expected, actual, case_sensitive, wildcard))
}

const fn byte_matches(expected: u8, actual: u8, case_sensitive: bool, wildcard: u8) -> bool {
    expected == wildcard
        || expected == actual
        || (!case_sensitive && expected.eq_ignore_ascii_case(&actual))
}
