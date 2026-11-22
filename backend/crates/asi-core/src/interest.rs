//! Ocena „ciekawości” usługi (0-100), ta sama heurystyka co `frontend/src/interest.ts`.
//! Zmiana wag wymaga zmiany w obu miejscach (test niżej pilnuje wartości).

use crate::export::ResultRow;

fn category_weight(category: &str) -> f64 {
    match category {
        "admin_panel" => 40.0,
        "staging" => 35.0,
        "iot" | "interesting" => 30.0,
        "cms" => 15.0,
        "application" | "framework" => 10.0,
        _ => 5.0, // server i nieznane
    }
}

fn severity_bonus(severity: Option<&str>) -> f64 {
    match severity.map(str::to_lowercase).as_deref() {
        Some("critical") => 40.0,
        Some("high") => 30.0,
        Some("medium") => 20.0,
        Some("low") => 10.0,
        _ => 0.0,
    }
}

/// Suma wag kategorii × pewność / 100 plus bonus za priorytet z korekty, obcięta do 100.
pub fn score(row: &ResultRow) -> u8 {
    let detections: f64 = row
        .technologies
        .iter()
        .map(|d| category_weight(&d.category) * f64::from(d.confidence) / 100.0)
        .sum();
    // jak Math.round w JS dla wartości dodatnich
    (detections + severity_bonus(row.severity.as_deref()))
        .round()
        .min(100.0) as u8
}

/// Poziom zagrożenia: „wysoka” ≥ 60, „średnia” 30–59, „niska” < 30.
pub fn level(score: u8) -> &'static str {
    match score {
        60.. => "wysoka",
        30..=59 => "średnia",
        _ => "niska",
    }
}

pub const HINT: &str = "Ocena 0–100 = suma wag wykrytych kategorii × pewność (panel administracyjny 40, staging 35, IoT i interesujące 30, CMS 15, pozostałe 5–10) + priorytet z korekty (Low 10 … Critical 40).";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Detection;

    fn row(dets: &[(&str, u8)], severity: Option<&str>) -> ResultRow {
        ResultRow {
            technologies: dets
                .iter()
                .map(|(c, conf)| Detection {
                    signature_id: "t".into(),
                    name: "t".into(),
                    category: (*c).into(),
                    version: None,
                    confidence: *conf,
                    evidence: vec![],
                })
                .collect(),
            severity: severity.map(Into::into),
            ..Default::default()
        }
    }

    #[test]
    fn matches_frontend_heuristic() {
        let admin_high = score(&row(&[("admin_panel", 100)], Some("High")));
        assert_eq!((admin_high, level(admin_high)), (70, "wysoka"));
        assert_eq!(score(&row(&[], None)), 0);
        assert_eq!(level(0), "niska");
        assert_eq!(score(&row(&[("nieznana", 100)], None)), 5);
        assert_eq!(score(&row(&[("cms", 50)], Some("medium"))), 28); // 7.5 + 20 = 27.5 -> 28
        assert_eq!(level(30), "średnia");
        let capped = score(&row(
            &[("admin_panel", 100), ("staging", 100)],
            Some("critical"),
        ));
        assert_eq!(capped, 100);
    }
}
