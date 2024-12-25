pub fn sanitize_path(s: &str) -> String {
    ensure_no_trailing_slash(&ensure_no_leading_slash(s))
}

pub fn ensure_trailing_slash(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        return String::new();
    }

    let mut result = s.to_string();
    while !result.is_empty() && !result.ends_with('/') {
        result.push('/');
    }
    result
}

pub fn ensure_no_trailing_slash(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        return String::new();
    }

    let mut result = s.to_string();
    while !result.is_empty() && result.ends_with('/') {
        result.pop();
    }
    result
}

pub fn ensure_no_leading_slash(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        return String::new();
    }

    let mut result = s.to_string();
    while !result.is_empty() && result.starts_with('/') {
        result.remove(0);
    }
    result
}