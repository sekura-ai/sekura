use crate::errors::SekuraError;
use super::playwright::BrowserSession;

pub enum BrowserAction {
    Navigate(String),
    Click(String),
    Type(String, String),
    Screenshot,
    Evaluate(String),
    Wait(u64),
}

pub async fn execute_browser_action(
    session: &BrowserSession,
    action: &BrowserAction,
) -> Result<String, SekuraError> {
    match action {
        BrowserAction::Navigate(url) => session.navigate(url).await,
        BrowserAction::Click(selector) => {
            session.click(selector).await?;
            Ok("clicked".to_string())
        }
        BrowserAction::Type(selector, text) => {
            session.type_text(selector, text).await?;
            Ok("typed".to_string())
        }
        BrowserAction::Screenshot => {
            let data = session.screenshot().await?;
            Ok(format!("screenshot: {} bytes", data.len()))
        }
        BrowserAction::Evaluate(js) => session.evaluate(js).await,
        BrowserAction::Wait(ms) => {
            tokio::time::sleep(std::time::Duration::from_millis(*ms)).await;
            Ok(format!("waited {}ms", ms))
        }
    }
}

pub fn parse_browser_actions(llm_response: &str) -> Result<Vec<BrowserAction>, SekuraError> {
    let mut actions = Vec::new();

    for line in llm_response.lines() {
        let line = line.trim();
        if line.starts_with("NAVIGATE:") {
            actions.push(BrowserAction::Navigate(line[9..].trim().to_string()));
        } else if line.starts_with("CLICK:") {
            actions.push(BrowserAction::Click(line[6..].trim().to_string()));
        } else if line.starts_with("TYPE:") {
            let parts: Vec<&str> = line[5..].trim().splitn(2, ' ').collect();
            if parts.len() == 2 {
                actions.push(BrowserAction::Type(parts[0].to_string(), parts[1].to_string()));
            }
        } else if line.starts_with("SCREENSHOT") {
            actions.push(BrowserAction::Screenshot);
        } else if line.starts_with("EVAL:") {
            actions.push(BrowserAction::Evaluate(line[5..].trim().to_string()));
        } else if line.starts_with("WAIT:") {
            if let Ok(ms) = line[5..].trim().parse::<u64>() {
                actions.push(BrowserAction::Wait(ms));
            }
        }
    }

    Ok(actions)
}
