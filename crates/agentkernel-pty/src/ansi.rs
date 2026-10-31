/// Removes ANSI escape sequences (CSI, OSC, 2-byte escape codes, terminal titles, colors)
/// from the input string to optimize LLM token consumption and improve model readability.
pub fn strip_ansi(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            match chars.peek() {
                Some('[') => {
                    // CSI sequence: ESC [ ... final_byte (0x40..=0x7E)
                    chars.next(); // consume '['
                    for c in chars.by_ref() {
                        if (c as u32) >= 0x40 && (c as u32) <= 0x7E {
                            break;
                        }
                    }
                }
                Some(']') => {
                    // OSC sequence: ESC ] ... BEL (\x07) or ST (\x1b\)
                    chars.next(); // consume ']'
                    while let Some(c) = chars.next() {
                        if c == '\x07' {
                            break;
                        }
                        if c == '\x1b' && chars.peek() == Some(&'\\') {
                            chars.next(); // consume '\'
                            break;
                        }
                    }
                }
                Some('(') | Some(')') | Some('*') | Some('+') => {
                    // Charset selection: ESC ( X
                    chars.next();
                    chars.next();
                }
                Some('P') | Some('_') | Some('^') | Some('X') => {
                    // DCS / APC / PM / SOS: ESC <char> ... ST
                    chars.next();
                    while let Some(c) = chars.next() {
                        if c == '\x07' {
                            break;
                        }
                        if c == '\x1b' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                Some(&next_ch) if ('@'..='_').contains(&next_ch) => {
                    // 2-byte escape sequences like ESC M, ESC 7, ESC 8, ESC =
                    chars.next();
                }
                _ => {
                    // Unknown or solitary ESC, ignore it
                }
            }
        } else {
            result.push(ch);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_ansi_plain_text() {
        assert_eq!(strip_ansi("Hello, world!"), "Hello, world!");
        assert_eq!(strip_ansi(""), "");
    }

    #[test]
    fn test_strip_ansi_colors_and_styles() {
        let input = "\x1b[31mRed\x1b[0m \x1b[1;32mBold Green\x1b[0m \x1b[4;34mUnderline Blue\x1b[0m";
        assert_eq!(strip_ansi(input), "Red Bold Green Underline Blue");
    }

    #[test]
    fn test_strip_ansi_cursor_and_screen() {
        let input = "\x1b[2J\x1b[HSystem Ready:\x1b[?25h OK";
        assert_eq!(strip_ansi(input), "System Ready: OK");
    }

    #[test]
    fn test_strip_ansi_osc_window_title() {
        let input = "\x1b]0;User@Host: /workspace\x07cargo build --release\nCompiling...";
        assert_eq!(strip_ansi(input), "cargo build --release\nCompiling...");

        let input_st = "\x1b]2;Terminal Title\x1b\\Finished successfully!";
        assert_eq!(strip_ansi(input_st), "Finished successfully!");
    }

    #[test]
    fn test_strip_ansi_multiline_compiler_output() {
        let input = "\x1b[1m\x1b[38;5;9merror[E0308]\x1b[0m\x1b[1m: mismatched types\x1b[0m\n \
                     \x1b[38;5;12m--> \x1b[0msrc/main.rs:10:5\n  \
                     \x1b[38;5;12m|\x1b[0m\n\
                     \x1b[38;5;12m10 |\x1b[0m let x: u32 = \"hello\";";

        let expected = "error[E0308]: mismatched types\n \
                        --> src/main.rs:10:5\n  \
                        |\n\
                        10 | let x: u32 = \"hello\";";

        assert_eq!(strip_ansi(input), expected);
    }
}
