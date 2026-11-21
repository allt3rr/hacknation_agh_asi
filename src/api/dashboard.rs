use super::ApiResult;
use crate::auth::{AuthUser, Permission};
use crate::db;
use crate::model::Observation;
use crate::state::AppState;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const TOP_TECHNOLOGIES: usize = 30;
const RECENT_CHANGES: i64 = 200;

/// Kategorie detekcji pokazywane jako "najważniejsze znaleziska".
const NOTABLE_CATEGORIES: [&str; 4] = ["admin_panel", "staging", "interesting", "iot"];

pub fn routes() -> Router<AppState> {
    Router::new().route("/dashboard", get(dashboard))
}

#[derive(Serialize)]
struct NotableFinding {
    key: String,
    name: String,
    category: String,
    confidence: u8,
    title: Option<String>,
}

async fn dashboard(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    user.require(Permission::Read)?;

    let counts = db::counts(&st.db).await?;
    let latest_run = db::latest_finished_run(&st.db).await?;

    let (observations, changes) = match &latest_run {
        Some(run) => (
            db::load_observations(&st.db, &st.crypto, &run.id).await?,
            db::list_changes(&st.db, &st.crypto, &run.id, RECENT_CHANGES).await?,
        ),
        None => (Vec::new(), Vec::new()),
    };

    Ok(Json(json!({
        "counts": counts,
        "latest_run": latest_run,
        "services": observations.len(),
        "technologies": top_technologies(&observations),
        "interesting": notable_findings(&observations),
        "changes": changes,
        "scan_running": st.scan_running(),
    })))
}

/// Najczęściej wykrywane technologie: (nazwa [kategoria], liczba usług).
fn top_technologies(observations: &[Observation]) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for obs in observations {
        for detection in &obs.detections {
            let label = format!("{} [{}]", detection.name, detection.category);
            *counts.entry(label).or_default() += 1;
        }
    }

    let mut sorted: Vec<(String, usize)> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.truncate(TOP_TECHNOLOGIES);
    sorted
}

fn notable_findings(observations: &[Observation]) -> Vec<NotableFinding> {
    let mut findings = Vec::new();
    for obs in observations {
        for detection in &obs.detections {
            if !NOTABLE_CATEGORIES.contains(&detection.category.as_str()) {
                continue;
            }
            findings.push(NotableFinding {
                key: obs.key(),
                name: detection.name.clone(),
                category: detection.category.clone(),
                confidence: detection.confidence,
                title: obs.http.as_ref().and_then(|http| http.title.clone()),
            });
        }
    }
    findings
}
