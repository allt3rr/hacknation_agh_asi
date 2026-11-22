//! Raport PDF przebiegu (A4 poziomo). Treść jak dawny raport w przeglądarce: metadane, poziomy
//! zagrożeń, usługi, zmiany i legenda. Dane ze skanu trafiają do PDF wyłącznie jako tekst.

use anyhow::{anyhow, Result};
use asi_core::export::ResultRow;
use asi_core::interest;
use asi_db::runs::RunView;
use asi_db::views::ChangeRow;
use genpdf::elements::{FrameCellDecorator, LinearLayout, Paragraph, TableLayout};
use genpdf::fonts::{FontData, FontFamily};
use genpdf::style::{Color, Style};
use genpdf::{Document, Element, SimplePageDecorator, Size};
use serde_json::Value;
use time::macros::format_description;
use time::OffsetDateTime;

// Monoid (licencja MIT, backend/assets/fonts/LICENSE-Monoid.txt): pełny zestaw polskich znaków.
static FONT_REGULAR: &[u8] = include_bytes!("../../../assets/fonts/Monoid-Regular.ttf");
static FONT_BOLD: &[u8] = include_bytes!("../../../assets/fonts/Monoid-Bold.ttf");

const LEVELS: [(&str, &str, Color); 3] = [
    ("wysoka", "Zagrożenie wysokie", Color::Rgb(200, 30, 30)),
    ("średnia", "Zagrożenie średnie", Color::Rgb(154, 74, 5)),
    ("niska", "Zagrożenie niskie", Color::Rgb(22, 101, 52)),
];
const ACCENT: Color = Color::Rgb(79, 70, 229);
const MUTED: Color = Color::Rgb(85, 96, 116);
/// Najdłuższy ciąg bez spacji w komórce: dłuższe są dzielone, żeby nie wychodziły poza kolumnę.
const MAX_WORD: usize = 24;
const MAX_CELL: usize = 160;

pub struct ReportInput<'a> {
    pub run: &'a RunView,
    pub rows: &'a [ResultRow],
    pub changes: &'a [ChangeRow],
    pub generated_by: &'a str,
    pub now: OffsetDateTime,
}

pub fn render(input: &ReportInput) -> Result<Vec<u8>> {
    let font = |b: &[u8]| FontData::new(b.to_vec(), None).map_err(|e| anyhow!("czcionka: {e}"));
    let family = FontFamily {
        regular: font(FONT_REGULAR)?,
        bold: font(FONT_BOLD)?,
        italic: font(FONT_REGULAR)?,
        bold_italic: font(FONT_BOLD)?,
    };
    let mut doc = Document::new(family);
    let started = fmt_date(input.run.started_at.unwrap_or(input.run.created_at));
    doc.set_title(format!("Raport ASI {started}"));
    doc.set_paper_size(Size::new(297, 210));
    doc.set_font_size(7);
    doc.set_line_spacing(1.15);
    let mut decorator = SimplePageDecorator::new();
    decorator.set_margins(10);
    doc.set_page_decorator(decorator);

    let mut scored: Vec<(u8, &ResultRow)> =
        input.rows.iter().map(|r| (interest::score(r), r)).collect();
    scored.sort_by_key(|(score, _)| std::cmp::Reverse(*score));

    let h1 = Style::new().bold().with_font_size(16).with_color(ACCENT);
    let h2 = Style::new().bold().with_font_size(10);
    let muted = Style::new().with_color(MUTED);

    doc.push(Paragraph::new("Raport z przebiegu skanu").styled(h1));
    doc.push(
        Paragraph::new(format!(
            "Attack Surface Intelligence · przebieg z {started} · wygenerowano {} UTC",
            fmt_date(input.now)
        ))
        .styled(muted),
    );

    section(&mut doc, "Przebieg", h2);
    let run = input.run;
    let status = match &run.reason {
        Some(r) => format!("{} ({r})", status_label(&run.status)),
        None => status_label(&run.status).to_string(),
    };
    let meta = [
        (
            "Rodzaj",
            if run.kind == "import" {
                "import".to_string()
            } else {
                "skan".to_string()
            },
        ),
        ("Status", status),
        ("Start", started.clone()),
        ("Koniec", run.finished_at.map(fmt_date).unwrap_or_default()),
        ("Czas trwania", fmt_duration(run.duration_ms)),
        ("Pokrycie", coverage_text(&run.coverage)),
        ("Identyfikator", run.id.to_string()),
        ("Wygenerował", input.generated_by.to_string()),
    ];
    let mut table = framed(vec![1, 5]);
    for (k, v) in meta {
        // szeroka kolumna: UUID i pokrycie bez dzielenia
        push_row_with(&mut table, &[(k, muted), (&v, Style::new())], 64)?;
    }
    doc.push(table);

    section(&mut doc, "Podsumowanie zagrożeń", h2);
    let counts: Vec<usize> = LEVELS
        .iter()
        .map(|(l, ..)| {
            scored
                .iter()
                .filter(|(s, _)| interest::level(*s) == *l)
                .count()
        })
        .collect();
    let mut summary = framed(vec![1, 1, 1, 1, 1]);
    let total = input.rows.len().to_string();
    let changes = input.changes.len().to_string();
    let cells: Vec<(String, String, Color)> =
        std::iter::once(("Usługi".to_string(), total, ACCENT))
            .chain(
                LEVELS
                    .iter()
                    .zip(&counts)
                    .map(|((_, t, c), n)| (t.to_string(), n.to_string(), *c)),
            )
            .chain(std::iter::once((
                "Zmiany".to_string(),
                changes,
                Color::Rgb(8, 145, 178),
            )))
            .collect();
    let mut row = summary.row();
    for (label, n, color) in &cells {
        let mut cell = LinearLayout::vertical();
        cell.push(Paragraph::new(label.as_str()).styled(muted));
        cell.push(
            Paragraph::new(n.as_str())
                .styled(Style::new().bold().with_font_size(14).with_color(*color)),
        );
        row.push_element(cell.padded(1));
    }
    row.push().map_err(|e| anyhow!("tabela: {e}"))?;
    doc.push(summary);

    section(&mut doc, "Usługi według poziomu zagrożenia", h2);
    if scored.is_empty() {
        doc.push(Paragraph::new("Brak usług w tym przebiegu.").styled(muted));
    }
    for ((level, title, color), n) in LEVELS.iter().zip(&counts) {
        if *n == 0 {
            continue;
        }
        doc.push(
            Paragraph::new(format!("{title} ({n})"))
                .styled(Style::new().bold().with_font_size(9).with_color(*color))
                .padded((2, 0, 1, 0)),
        );
        let mut t = framed(vec![2, 5, 3, 3, 5, 6, 8, 3]);
        let head = [
            "Ocena",
            "Host",
            "Port",
            "Usługa",
            "Produkt",
            "Technologie",
            "Tytuł HTTP",
            "Priorytet",
        ];
        push_row(&mut t, &head.map(|h| (h, Style::new().bold())))?;
        for (score, r) in scored.iter().filter(|(s, _)| interest::level(*s) == *level) {
            let host = match &r.hostname {
                Some(h) => format!("{} ({h})", r.ip),
                None => r.ip.clone(),
            };
            let product = [r.product.as_deref(), r.version.as_deref()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
            let tech = r
                .technologies
                .iter()
                .map(|d| match &d.version {
                    Some(v) => format!("{} {v}", d.name),
                    None => d.name.clone(),
                })
                .collect::<Vec<_>>()
                .join(", ");
            let title = r
                .http
                .as_ref()
                .and_then(|h| h.title.clone())
                .unwrap_or_default();
            let values = [
                score.to_string(),
                host,
                format!("{}/{}", r.port, r.proto),
                r.service.clone().unwrap_or_default(),
                product,
                tech,
                title,
                r.severity.clone().unwrap_or_default(),
            ];
            let plain = Style::new();
            push_row(&mut t, &values.each_ref().map(|v| (v.as_str(), plain)))?;
        }
        doc.push(t);
    }

    section(&mut doc, "Zmiany względem poprzedniego przebiegu", h2);
    if input.changes.is_empty() {
        doc.push(Paragraph::new("Brak zmian względem poprzedniego przebiegu.").styled(muted));
    } else {
        let mut t = framed(vec![2, 4, 2, 5, 5]);
        push_row(
            &mut t,
            &["Typ", "Usługa / host", "Pole", "Przed", "Po"].map(|h| (h, Style::new().bold())),
        )?;
        for c in input.changes {
            let values = [
                kind_label(&c.kind).to_string(),
                c.entity_key.clone(),
                c.field.clone().unwrap_or_default(),
                c.before.clone().unwrap_or_default(),
                c.after.clone().unwrap_or_default(),
            ];
            push_row(
                &mut t,
                &values.each_ref().map(|v| (v.as_str(), Style::new())),
            )?;
        }
        doc.push(t);
    }

    section(&mut doc, "Legenda oceny", h2);
    doc.push(Paragraph::new(format!(
        "{} Poziomy: wysokie ≥ 60, średnie 30–59, niskie < 30.",
        interest::HINT
    )));

    let mut out = Vec::new();
    doc.render(&mut out)
        .map_err(|e| anyhow!("render PDF: {e}"))?;
    Ok(out)
}

fn section(doc: &mut Document, title: &str, style: Style) {
    doc.push(Paragraph::new(title).styled(style).padded((4, 0, 1, 0)));
}

fn framed(widths: Vec<usize>) -> TableLayout {
    let mut t = TableLayout::new(widths);
    t.set_cell_decorator(FrameCellDecorator::new(true, true, false));
    t
}

fn push_row(table: &mut TableLayout, cells: &[(&str, Style)]) -> Result<()> {
    push_row_with(table, cells, MAX_WORD)
}

fn push_row_with(table: &mut TableLayout, cells: &[(&str, Style)], max_word: usize) -> Result<()> {
    let mut row = table.row();
    for (text, style) in cells {
        row.push_element(
            Paragraph::new(cell_text(text, max_word))
                .styled(*style)
                .padded(1),
        );
    }
    row.push().map_err(|e| anyhow!("tabela: {e}"))
}

/// Obcina długie wartości i dzieli ciągi bez spacji, bo genpdf zawija tekst tylko na spacjach.
fn cell_text(text: &str, max_word: usize) -> String {
    let mut chars: Vec<char> = text.chars().filter(|c| !c.is_control()).collect();
    if chars.len() > MAX_CELL {
        chars.truncate(MAX_CELL - 1);
        chars.push('…');
    }
    let mut out = String::with_capacity(chars.len() + 8);
    let mut run = 0;
    for c in chars {
        if c.is_whitespace() {
            run = 0;
        } else {
            if run == max_word {
                out.push(' ');
                run = 0;
            }
            run += 1;
        }
        out.push(c);
    }
    out
}

fn fmt_date(t: OffsetDateTime) -> String {
    t.to_offset(time::UtcOffset::UTC)
        .format(format_description!("[year]-[month]-[day] [hour]:[minute]"))
        .unwrap_or_default()
}

fn fmt_duration(ms: Option<i64>) -> String {
    let Some(ms) = ms else { return String::new() };
    let total = (ms + 500) / 1000;
    let (h, m, s) = (total / 3600, (total % 3600) / 60, total % 60);
    match (h, m) {
        (0, 0) => format!("{s} s"),
        (0, _) => format!("{m} min {s} s"),
        _ => format!("{h} h {m} min {s} s"),
    }
}

fn coverage_text(c: &Value) -> String {
    let n = |k: &str| c.get(k).and_then(Value::as_u64);
    let mut parts = Vec::new();
    if let Some(planned) = n("planned") {
        parts.push(format!("cele: {}/{planned}", n("scanned").unwrap_or(0)));
    }
    if let Some(v) = n("live_hosts") {
        parts.push(format!("hosty: {v}"));
    }
    if let Some(v) = n("services") {
        parts.push(format!("usługi: {v}"));
    }
    for (k, label) in [("pending", "zaległe"), ("failed", "nieudane")] {
        if let Some(v) = n(k).filter(|v| *v > 0) {
            parts.push(format!("{label}: {v}"));
        }
    }
    parts.join(", ")
}

fn status_label(s: &str) -> &str {
    match s {
        "queued" => "w kolejce",
        "running" => "w toku",
        "done" => "zakończony",
        "partial" => "częściowy",
        "failed" => "błąd",
        "cancelled" => "anulowany",
        other => other,
    }
}

fn kind_label(k: &str) -> &str {
    match k {
        "new" => "nowa",
        "gone" => "zniknęła",
        "changed" => "zmiana",
        "host_inactive" => "host nieaktywny",
        "host_returned" => "host wrócił",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asi_core::export::HttpView;
    use asi_core::model::Detection;
    use serde_json::json;
    use uuid::Uuid;

    fn run() -> RunView {
        RunView {
            id: Uuid::nil(),
            kind: "scan".into(),
            status: "done".into(),
            reason: None,
            coverage: json!({ "planned": 3, "scanned": 3, "live_hosts": 2, "services": 2 }),
            started_at: Some(OffsetDateTime::UNIX_EPOCH),
            finished_at: Some(OffsetDateTime::UNIX_EPOCH),
            duration_ms: Some(61_000),
            hosts_total: 3,
            hosts_done: 3,
            triggered_by: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            vuln_state: "none".into(),
            vuln_reason: None,
            vuln_summary: json!({}),
            dd_export: None,
        }
    }

    fn input<'a>(
        run: &'a RunView,
        rows: &'a [ResultRow],
        changes: &'a [ChangeRow],
    ) -> ReportInput<'a> {
        ReportInput {
            run,
            rows,
            changes,
            generated_by: "żółć",
            now: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn renders_pdf_with_long_values_and_polish_text() {
        let admin = ResultRow {
            ip: "10.0.0.1".into(),
            port: 443,
            proto: "tcp".into(),
            severity: Some("high".into()),
            technologies: vec![Detection {
                signature_id: "admin".into(),
                name: "Panel administracyjny".into(),
                category: "admin_panel".into(),
                version: None,
                confidence: 100,
                evidence: vec![],
            }],
            http: Some(HttpView {
                title: Some("A".repeat(300)),
                ..Default::default()
            }),
            ..Default::default()
        };
        let plain = ResultRow {
            ip: "10.0.0.2".into(),
            port: 22,
            proto: "tcp".into(),
            ..Default::default()
        };
        let rows = [admin, plain];
        let changes = [ChangeRow {
            id: 1,
            kind: "changed".into(),
            entity_key: "10.0.0.1:443/tcp".into(),
            ip: "10.0.0.1".into(),
            field: Some("version".into()),
            before: Some("1.0".into()),
            after: Some("ąęłóśźż".repeat(40)),
            created_at: OffsetDateTime::UNIX_EPOCH,
        }];
        let r = run();
        let pdf = render(&input(&r, &rows, &changes)).unwrap();
        assert!(pdf.starts_with(b"%PDF-"));
        assert!(
            pdf.windows(8).any(|w| w == b"FontFile"),
            "czcionka osadzona"
        );
        assert!(pdf.len() > 10_000);
    }

    #[test]
    fn renders_empty_run() {
        let r = run();
        assert!(render(&input(&r, &[], &[])).unwrap().starts_with(b"%PDF-"));
    }

    #[test]
    fn long_words_are_split_and_cells_capped() {
        let t = cell_text(&"x".repeat(300), MAX_WORD);
        assert!(t.chars().count() <= MAX_CELL + MAX_CELL / MAX_WORD + 1);
        assert!(t.split(' ').all(|w| w.chars().count() <= MAX_WORD));
        assert!(t.ends_with('…'));
        assert_eq!(fmt_duration(Some(61_000)), "1 min 1 s");
        let uuid = "8880fa0d-44db-4e3e-8d38-60de9a5b591b";
        assert_eq!(cell_text(uuid, 64), uuid);
    }
}
