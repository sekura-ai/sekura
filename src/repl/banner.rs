use console::{style, Term, Key};

/// 256-color codes for the brick rendering.
const FILL_COLOR: u8 = 209; // salmon/peach brick fill
const OUTLINE_COLOR: u8 = 131; // darker indian red for mortar/outlines

/// Each letter is a 5-wide × 5-tall bitmap.
type Letter = [[bool; 5]; 5];

const S: Letter = [
    [false, true,  true,  true,  true ],
    [true,  false, false, false, false],
    [false, true,  true,  true,  false],
    [false, false, false, false, true ],
    [true,  true,  true,  true,  false],
];

const E: Letter = [
    [true,  true,  true,  true,  true ],
    [true,  false, false, false, false],
    [true,  true,  true,  true,  false],
    [true,  false, false, false, false],
    [true,  true,  true,  true,  true ],
];

const K: Letter = [
    [true,  false, false, false, true ],
    [true,  false, false, true,  false],
    [true,  true,  true,  false, false],
    [true,  false, false, true,  false],
    [true,  false, false, false, true ],
];

const U: Letter = [
    [true,  false, false, false, true ],
    [true,  false, false, false, true ],
    [true,  false, false, false, true ],
    [true,  false, false, false, true ],
    [false, true,  true,  true,  false],
];

const R: Letter = [
    [true,  true,  true,  true,  false],
    [true,  false, false, false, true ],
    [true,  true,  true,  true,  false],
    [true,  false, true,  false, false],
    [true,  false, false, true,  false],
];

const A: Letter = [
    [false, true,  true,  true,  false],
    [true,  false, false, false, true ],
    [true,  true,  true,  true,  true ],
    [true,  false, false, false, true ],
    [true,  false, false, false, true ],
];

/// Show a full-screen splash with brick-rendered "SEKURA" art.
/// Waits for Enter, then clears and returns.
pub fn show_splash() {
    let term = Term::stdout();
    let _ = term.clear_screen();

    let version = env!("CARGO_PKG_VERSION");
    let git_hash = option_env!("GIT_HASH").unwrap_or("dev");

    // Compute brick art lines first so we know the width
    let bitmap = combine_letters(&[&S, &E, &K, &U, &R, &A], 1);
    let art_lines = render_brick_grid(&bitmap);
    let art_visible_width = bitmap[0].len() * 3 + 1;

    // Determine horizontal padding to center art
    let (_, term_cols) = term.size();
    let term_w = term_cols as usize;
    let pad_n = if term_w > art_visible_width + 4 {
        (term_w - art_visible_width) / 2
    } else {
        2
    };
    let pad = " ".repeat(pad_n);

    // Welcome box
    let box_inner = "  \u{2731} Welcome to Sekura  ";
    let box_w = box_inner.len() + 2; // +2 for side borders
    let box_pad_n = if term_w > box_w + 4 {
        (term_w - box_w) / 2
    } else {
        2
    };
    let box_pad = " ".repeat(box_pad_n);

    println!();
    println!(
        "{}{}{}{}",
        box_pad,
        style("\u{250c}").color256(OUTLINE_COLOR),
        style("\u{2500}".repeat(box_inner.len())).color256(OUTLINE_COLOR),
        style("\u{2510}").color256(OUTLINE_COLOR),
    );
    println!(
        "{}{}  {} Welcome to {}  {}",
        box_pad,
        style("\u{2502}").color256(OUTLINE_COLOR),
        style("\u{2731}").color256(FILL_COLOR).bold(),
        style("Sekura").white().bold(),
        style("\u{2502}").color256(OUTLINE_COLOR),
    );
    println!(
        "{}{}{}{}",
        box_pad,
        style("\u{2514}").color256(OUTLINE_COLOR),
        style("\u{2500}".repeat(box_inner.len())).color256(OUTLINE_COLOR),
        style("\u{2518}").color256(OUTLINE_COLOR),
    );
    println!();

    // Brick art
    for line in &art_lines {
        println!("{}{}", pad, line);
    }
    println!();

    // Version
    println!(
        "{}  {} {} ({})",
        pad,
        style("v").dim(),
        style(version).white(),
        style(git_hash).dim(),
    );
    println!();

    // Usage guide
    let guide: &[(&str, &str)] = &[
        ("/init",                              "Set up Docker image, container, and LLM"),
        ("/scan --target <url> [--repo <path>]", "Start a penetration test"),
        ("/status",                            "Show scan progress"),
        ("/findings",                          "View discovered vulnerabilities"),
        ("/stop",                              "Cancel a running scan"),
        ("/help",                              "List all commands"),
    ];
    println!("{}  {}", pad, style("Quick Start:").white().bold());
    println!();
    for (cmd, desc) in guide {
        println!(
            "{}    {:<40} {}",
            pad,
            style(cmd).color256(FILL_COLOR),
            style(desc).dim(),
        );
    }
    println!();

    // Press Enter prompt
    println!(
        "{}  Press {} to continue",
        pad,
        style("Enter").white().bold(),
    );

    // Wait for Enter (or Escape)
    loop {
        match term.read_key() {
            Ok(Key::Enter) => break,
            Ok(Key::Escape) => break,
            Err(_) => break,
            _ => {}
        }
    }

    // Clear and show brief post-splash header
    let _ = term.clear_screen();
    println!(
        "  {} {}",
        style("Sekura").color256(FILL_COLOR).bold(),
        style(format!("v{}", version)).dim(),
    );
    println!(
        "  {} {}",
        style("Type").dim(),
        style("/help").white().bold(),
    );
    println!();
}

/// Combine letter bitmaps into a single wide bitmap with gaps between letters.
fn combine_letters(letters: &[&Letter], gap: usize) -> Vec<Vec<bool>> {
    let letter_w = 5;
    let letter_h = 5;
    let total_w = letters.len() * letter_w + (letters.len().saturating_sub(1)) * gap;
    let mut bitmap = vec![vec![false; total_w]; letter_h];

    for (li, letter) in letters.iter().enumerate() {
        let x_offset = li * (letter_w + gap);
        for y in 0..letter_h {
            for x in 0..letter_w {
                bitmap[y][x_offset + x] = letter[y][x];
            }
        }
    }
    bitmap
}

/// Render a boolean pixel grid as box-drawing brick art with two-tone coloring.
///
/// Each pixel becomes a 3-char-wide × 2-row-tall brick cell.
/// Output dimensions: (width * 3 + 1) columns × (height * 2 + 1) rows.
fn render_brick_grid(bitmap: &[Vec<bool>]) -> Vec<String> {
    let h = bitmap.len();
    if h == 0 {
        return vec![];
    }
    let w = bitmap[0].len();
    let out_h = h * 2 + 1;
    let out_w = w * 3 + 1;

    let mut lines = Vec::with_capacity(out_h);

    for out_y in 0..out_h {
        let mut line = String::new();
        let is_border_y = out_y % 2 == 0;

        for out_x in 0..out_w {
            let is_border_x = out_x % 3 == 0;

            if is_border_y && is_border_x {
                // Grid intersection — pick the right box-drawing character
                let by = out_y / 2; // border row index (0..=h)
                let bx = out_x / 3; // border col index (0..=w)

                let ul = bx > 0 && by > 0 && bitmap[by - 1][bx - 1];
                let ur = bx < w && by > 0 && bitmap[by - 1][bx];
                let dl = bx > 0 && by < h && bitmap[by][bx - 1];
                let dr = bx < w && by < h && bitmap[by][bx];

                let has_up = ul || ur;
                let has_down = dl || dr;
                let has_left = ul || dl;
                let has_right = ur || dr;

                let ch = box_char(has_up, has_down, has_left, has_right);
                if ch == ' ' {
                    line.push(' ');
                } else {
                    line.push_str(&format!("{}", style(ch).color256(OUTLINE_COLOR)));
                }
            } else if is_border_y && !is_border_x {
                // Horizontal border segment between two rows
                let by = out_y / 2;
                let px = out_x / 3;

                let above = by > 0 && px < w && bitmap[by - 1][px];
                let below = by < h && px < w && bitmap[by][px];

                if above || below {
                    line.push_str(&format!("{}", style('─').color256(OUTLINE_COLOR)));
                } else {
                    line.push(' ');
                }
            } else if !is_border_y && is_border_x {
                // Vertical border segment between two columns
                let py = (out_y - 1) / 2;
                let bx = out_x / 3;

                let to_left = bx > 0 && bitmap[py][bx - 1];
                let to_right = bx < w && bitmap[py][bx];

                if to_left || to_right {
                    line.push_str(&format!("{}", style('│').color256(OUTLINE_COLOR)));
                } else {
                    line.push(' ');
                }
            } else {
                // Fill area
                let py = (out_y - 1) / 2;
                let px = out_x / 3;

                if px < w && bitmap[py][px] {
                    line.push_str(&format!("{}", style('█').color256(FILL_COLOR)));
                } else {
                    line.push(' ');
                }
            }
        }

        lines.push(line);
    }

    lines
}

/// Select the box-drawing character for a grid intersection based on
/// which of the four cardinal directions have a connecting border.
fn box_char(up: bool, down: bool, left: bool, right: bool) -> char {
    match (up, down, left, right) {
        (false, false, false, false) => ' ',
        // Four-way
        (true,  true,  true,  true ) => '┼',
        // Three-way
        (false, true,  true,  true ) => '┬',
        (true,  false, true,  true ) => '┴',
        (true,  true,  false, true ) => '├',
        (true,  true,  true,  false) => '┤',
        // Two-way
        (true,  true,  false, false) => '│',
        (false, false, true,  true ) => '─',
        (false, true,  false, true ) => '┌',
        (false, true,  true,  false) => '┐',
        (true,  false, false, true ) => '└',
        (true,  false, true,  false) => '┘',
        // Single direction — extend the line
        (true,  false, false, false) => '│',
        (false, true,  false, false) => '│',
        (false, false, true,  false) => '─',
        (false, false, false, true ) => '─',
    }
}
