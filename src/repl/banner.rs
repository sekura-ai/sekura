use console::{style, Term, Key};
use tui_banner::{Align, Banner, ColorMode, Fill, Gradient, GradientDirection, Palette};

/// Color palette — warm gradient matching the Sekura brand.
const BRAND: u8 = 209;      // salmon/peach — primary brand
const BRAND_DIM: u8 = 131;  // darker indian red
const DIM: u8 = 240;        // dim text

/// The separator character (horizontal ellipsis).
const SEP_CHAR: char = '\u{2026}'; // …

const TAGLINE: &str = "Autonomous AI Penetration Testing Agent";

/// Hacker-in-hoodie ASCII art (each line is 20 chars wide).
const HACKER_ART: &[&str] = &[
    "       \u{2584}\u{2588}\u{2588}\u{2588}\u{2588}\u{2584}       ",
    "     \u{2584}\u{2588}\u{2588}\u{2580}\u{2580}\u{2580}\u{2580}\u{2588}\u{2588}\u{2584}     ",
    "    \u{2588}\u{2588}\u{2580}      \u{2580}\u{2588}\u{2588}    ",
    "    \u{2588}\u{2588}  \u{25a0}  \u{25a0}  \u{2588}\u{2588}    ",
    "    \u{2588}\u{2588}        \u{2588}\u{2588}    ",
    "     \u{2588}\u{2588}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2588}\u{2588}     ",
    "      \u{2580}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2580}      ",
    "     \u{2590}\u{2588} \u{2588}\u{2588}\u{2588}\u{2588} \u{2588}\u{258c}     ",
];
const HACKER_W: usize = 20;
const HACKER_EYE_LINE: usize = 3;

/// Mini hacker logo for inline display (each line is 6 chars wide).
const MINI_LOGO: &[&str] = &[
    " \u{2584}\u{2588}\u{2588}\u{2584} ",
    "\u{2588}\u{2588}\u{25a0}\u{25a0}\u{2588}\u{2588}",
    " \u{2580}\u{2588}\u{2588}\u{2580} ",
];

/// Show the full-screen splash banner.
/// Waits for Enter, then clears and returns.
pub fn show_splash() {
    let term = Term::stdout();
    let _ = term.clear_screen();

    let version = env!("CARGO_PKG_VERSION");
    let git_hash = option_env!("GIT_HASH").unwrap_or("dev");

    let (_, term_cols) = term.size();
    let term_w = term_cols as usize;

    let center = |text_w: usize| -> String {
        if term_w > text_w + 4 {
            " ".repeat((term_w - text_w) / 2)
        } else {
            "  ".to_string()
        }
    };

    // ── Render the FIGlet banner via tui-banner ──
    let palette = Palette::from_hex(&[
        "#FFD7AF", // light peach (glow)
        "#FF875F", // salmon (brand core)
        "#D75F5F", // indian red (mid)
        "#875FAF", // muted purple (deep)
    ]);
    let gradient = Gradient::new(palette.colors().to_vec(), GradientDirection::Diagonal);

    // Determine if terminal is wide enough for side-by-side logo + banner
    let logo_gap = 3;
    let min_banner_w = 50;
    let show_logo = term_w >= HACKER_W + logo_gap + min_banner_w + 4;

    let banner_field_w = if show_logo {
        term_w.saturating_sub(HACKER_W + logo_gap + 4).min(90)
    } else {
        term_w
    };

    let banner_text = match Banner::new("SEKURA") {
        Ok(b) => b
            .gradient(gradient)
            .fill(Fill::Keep)
            .align(Align::Center)
            .trim_vertical(true)
            .edge_shade(0.35, '\u{2591}') // ░
            .color_mode(ColorMode::TrueColor)
            .width(banner_field_w)
            .render(),
        Err(_) => {
            format!(
                "{}\n",
                style("SEKURA").color256(BRAND).bold()
            )
        }
    };

    // ── Banner + Logo ──
    println!();
    if show_logo {
        let banner_lines: Vec<&str> = banner_text.lines().collect();
        let logo_lines = styled_hacker_art();
        let max_h = banner_lines.len().max(logo_lines.len());
        let combined_w = HACKER_W + logo_gap + banner_field_w;
        let left_pad = if term_w > combined_w + 2 {
            (term_w - combined_w) / 2
        } else {
            1
        };
        let pad_str = " ".repeat(left_pad);
        let gap_str = " ".repeat(logo_gap);
        let empty_logo = " ".repeat(HACKER_W);

        // Vertically center the logo against the banner
        let logo_offset = if max_h > logo_lines.len() {
            (max_h - logo_lines.len()) / 2
        } else {
            0
        };

        for i in 0..max_h {
            let logo_idx = i.checked_sub(logo_offset);
            let logo = match logo_idx {
                Some(idx) if idx < logo_lines.len() => &logo_lines[idx],
                _ => &empty_logo,
            };
            let banner = banner_lines.get(i).copied().unwrap_or("");
            println!("{}{}{}{}", pad_str, logo, gap_str, banner);
        }
    } else {
        print!("{}", banner_text);
    }

    // ── Version ──
    {
        let version_str = format!("v{} ({})", version, git_hash);
        let p = center(version_str.len());
        println!("{}{}", p, style(version_str).color256(DIM));
    }

    // ── Top separator ──
    let scene_w = term_w.min(76).max(40);
    let pad = center(scene_w);
    println!(
        "{}{}",
        pad,
        style(SEP_CHAR.to_string().repeat(scene_w)).color256(BRAND_DIM),
    );

    // ── Tagline ──
    {
        let p = center(TAGLINE.len());
        println!("{}{}", p, style(TAGLINE).white().bold());
    }

    // ── Bottom separator ──
    println!(
        "{}{}",
        pad,
        style(SEP_CHAR.to_string().repeat(scene_w)).color256(BRAND_DIM),
    );
    println!();

    // ── Authorization notice ──
    print_notice_box(&center);
    println!();

    // ── System initialized ──
    {
        let msg = "System initialized \u{2014} ready to scan";
        let p = center(msg.len() + 4);
        println!(
            "{}  {} {}",
            p,
            style("\u{2714}").green().bold(),
            style(msg).green(),
        );
    }
    println!();

    // ── Quick start ──
    let guide: &[(&str, &str)] = &[
        ("/init",                                 "Set up Docker, container, and LLM"),
        ("/scan --target <url> [--file <config>]", "Start a penetration test"),
        ("/status",                               "Show scan progress"),
        ("/findings",                             "View discovered vulnerabilities"),
        ("/help",                                 "List all commands"),
    ];
    {
        let p = center(56);
        println!("{}  {}", p, style("Quick Start:").white().bold());
        println!();
        for (cmd, desc) in guide {
            println!(
                "{}    {:<42} {}",
                p,
                style(cmd).color256(BRAND),
                style(desc).dim(),
            );
        }
    }
    println!();

    // ── Press Enter ──
    {
        let p = center(24);
        println!(
            "{}  Press {} to continue",
            p,
            style("Enter").white().bold(),
        );
    }

    loop {
        match term.read_key() {
            Ok(Key::Enter) => break,
            Ok(Key::Escape) => break,
            Err(_) => break,
            _ => {}
        }
    }

    // Clear and show brief post-splash header with mini logo
    let _ = term.clear_screen();
    let mini = styled_mini_logo();
    println!("  {}", mini[0]);
    println!(
        "  {}  {} {}  {}",
        mini[1],
        style("Sekura").color256(BRAND).bold(),
        style(format!("v{}", version)).dim(),
        style("\u{2714} ready").green().dim(),
    );
    println!(
        "  {}  {} {}",
        mini[2],
        style("Type").dim(),
        style("/help").white().bold(),
    );
    println!();
}

/// Render the hacker art lines with brand colors and green eyes.
fn styled_hacker_art() -> Vec<String> {
    HACKER_ART
        .iter()
        .enumerate()
        .map(|(i, line)| {
            if i == HACKER_EYE_LINE {
                let parts: Vec<&str> = line.split('\u{25a0}').collect();
                format!(
                    "{}{}{}{}{}",
                    style(parts[0]).color256(BRAND_DIM),
                    style("\u{25a0}").green().bold(),
                    style(parts[1]).color256(BRAND_DIM),
                    style("\u{25a0}").green().bold(),
                    style(parts[2]).color256(BRAND_DIM),
                )
            } else if i <= 6 {
                format!("{}", style(line).color256(BRAND_DIM))
            } else {
                format!("{}", style(line).color256(BRAND))
            }
        })
        .collect()
}

/// Render the mini hacker logo with brand colors and green eyes.
fn styled_mini_logo() -> Vec<String> {
    MINI_LOGO
        .iter()
        .enumerate()
        .map(|(i, line)| {
            if i == 1 {
                let parts: Vec<&str> = line.splitn(3, "\u{25a0}\u{25a0}").collect();
                format!(
                    "{}{}{}",
                    style(parts[0]).color256(BRAND),
                    style("\u{25a0}\u{25a0}").green().bold(),
                    style(parts.get(1).unwrap_or(&"")).color256(BRAND),
                )
            } else {
                format!("{}", style(line).color256(BRAND))
            }
        })
        .collect()
}

/// Print the "AUTHORIZED USE ONLY" notice inside a box-drawn border.
fn print_notice_box(center: &dyn Fn(usize) -> String) {
    let notice_lines: &[&str] = &[
        "This tool is intended for authorized security testing only.",
        "Only test systems you own or have explicit written permission to assess.",
        "Unauthorized access to computer systems is illegal.",
    ];

    let content_w = notice_lines.iter().map(|l| l.len()).max().unwrap_or(40);
    let inner_w = content_w + 4; // 2-char left + 2-char right margin
    let pad = center(inner_w + 2);

    let hbar = "\u{2500}".repeat(inner_w);

    // Top border
    println!(
        "{}{}{}{}",
        pad,
        style("\u{250c}").color256(BRAND_DIM),
        style(&hbar).color256(BRAND_DIM),
        style("\u{2510}").color256(BRAND_DIM),
    );

    // Warning header — centered
    {
        let header = "AUTHORIZED USE ONLY";
        let icon = "\u{26a0}";
        let text_w = 1 + 2 + header.len();
        let left = (inner_w.saturating_sub(text_w)) / 2;
        let right = inner_w.saturating_sub(text_w + left);
        println!(
            "{}{}{}{}  {}{}{}",
            pad,
            style("\u{2502}").color256(BRAND_DIM),
            " ".repeat(left),
            style(icon).color256(BRAND).bold(),
            style(header).color256(BRAND).bold(),
            " ".repeat(right),
            style("\u{2502}").color256(BRAND_DIM),
        );
    }

    // Separator
    {
        let sep = "\u{2500}".repeat(inner_w - 2);
        println!(
            "{}{} {} {}",
            pad,
            style("\u{2502}").color256(BRAND_DIM),
            style(sep).color256(BRAND_DIM),
            style("\u{2502}").color256(BRAND_DIM),
        );
    }

    // Notice lines
    for line in notice_lines {
        let right_pad = inner_w.saturating_sub(line.len() + 2);
        println!(
            "{}{}  {}{}{}",
            pad,
            style("\u{2502}").color256(BRAND_DIM),
            style(line).dim(),
            " ".repeat(right_pad),
            style("\u{2502}").color256(BRAND_DIM),
        );
    }

    // Bottom border
    println!(
        "{}{}{}{}",
        pad,
        style("\u{2514}").color256(BRAND_DIM),
        style(&hbar).color256(BRAND_DIM),
        style("\u{2518}").color256(BRAND_DIM),
    );
}
