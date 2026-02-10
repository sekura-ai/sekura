use console::{style, Term, Key};
use tui_banner::{Align, Banner, ColorMode, Fill, Gradient, GradientDirection, Palette};

/// Color palette — warm gradient matching the Sekura brand.
const BRAND: u8 = 209;      // salmon/peach — primary brand
const BRAND_DIM: u8 = 131;  // darker indian red
const DIM: u8 = 240;        // dim text

/// The separator character (horizontal ellipsis).
const SEP_CHAR: char = '\u{2026}'; // …

const TAGLINE: &str = "Autonomous AI Penetration Testing Agent";

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

    let banner_text = match Banner::new("SEKURA") {
        Ok(b) => b
            .gradient(gradient)
            .fill(Fill::Keep)
            .align(Align::Center)
            .trim_vertical(true)
            .edge_shade(0.35, '\u{2591}') // ░
            .color_mode(ColorMode::TrueColor)
            .width(term_w)
            .render(),
        Err(_) => {
            // Fallback if FIGlet font fails
            let p = center(6);
            format!(
                "{}{}\n",
                p,
                style("SEKURA").color256(BRAND).bold()
            )
        }
    };

    // ── Banner ──
    println!();
    print!("{}", banner_text);

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

    // Clear and show brief post-splash header
    let _ = term.clear_screen();
    println!(
        "  {} {}  {}",
        style("Sekura").color256(BRAND).bold(),
        style(format!("v{}", version)).dim(),
        style("\u{2714} ready").green().dim(),
    );
    println!(
        "  {} {}",
        style("Type").dim(),
        style("/help").white().bold(),
    );
    println!();
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
