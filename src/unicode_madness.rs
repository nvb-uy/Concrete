pub fn validate_and_normalize_domain(domain: &str) -> Option<String> {
    match idna::domain_to_ascii_strict(domain) {
        Ok(domain) => {
            let (domain, err) = idna::domain_to_unicode(&domain);
            if err.is_err() {
                None
            } else {
                Some(domain)
            }
        }
        Err(_) => None,
    }
}
