use std::collections::HashSet;

pub fn remove_duplicates(strings: &mut Vec<String>, stable: bool, lowercase: bool) {
    if stable {
        let mut seen = HashSet::new();
        let mut i = 0;
        while i < strings.len() {
            if lowercase {
                strings[i].make_ascii_lowercase();
            }
            if strings[i].trim().is_empty() || !seen.insert(strings[i].clone()) {
                strings.remove(i);
            } else {
                i += 1;
            }
        }
    } else {
        if lowercase {
            strings.iter_mut().for_each(|s| s.make_ascii_lowercase());
        }
        strings.retain(|s| !s.trim().is_empty());
        strings.sort();
        strings.dedup();
    }
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_string() {
        let strings = vec![
            String::from("Orange"),
            String::from("Apple"),
            String::from("banana"),
            String::from(""),
            String::from("banana"),
            String::from(""),
            String::from(""),
            String::from(""),
            String::from("orange"),
            String::from(""),
        ];

        let mut strings1 = strings.clone();
        let mut strings2 = strings.clone();
        let mut strings3 = strings.clone();
        let mut strings4 = strings.clone();

        remove_duplicates(&mut strings1, true, true);
        assert_eq!(strings1, vec!["orange".to_string(), "apple".to_string(), "banana".to_string()]);

        remove_duplicates(&mut strings2, true, false);
        assert_eq!(
            strings2,
            vec!["Orange".to_string(), "Apple".to_string(), "banana".to_string(), "orange".to_string()]
        );

        remove_duplicates(&mut strings3, false, true);
        assert_eq!(strings3, vec!["apple".to_string(), "banana".to_string(), "orange".to_string()]);

        remove_duplicates(&mut strings4, false, false);
        assert_eq!(
            strings4,
            vec!["Apple".to_string(), "Orange".to_string(), "banana".to_string(), "orange".to_string()]
        );
    }
}
