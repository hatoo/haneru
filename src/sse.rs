pub fn replace_cr(text: &str) -> String {
    text.replace('\r', "&#x0D;").replace('\n', "&#x0A;")
}
