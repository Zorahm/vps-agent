//! Page screenshots through a headless Chromium installed on the server.

use super::fs::{read_bytes, MAX_TRANSFER};
use super::image::prepare_image;
use super::{run_capture, run_ok, ToolOutput, ToolResult};
use crate::audit::audit;
use crate::ctx::Ctx;
use crate::runas::resolve;
use serde::Deserialize;
use std::time::Instant;

const FIND_BROWSER: &str = "command -v chromium || command -v chromium-browser || command -v google-chrome || command -v google-chrome-stable";
const TIMEOUT_SECS: &str = "45";

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ScreenshotParams {
    /// Page to capture: an http:// or https:// URL, typically http://127.0.0.1:<port>/.
    pub url: String,
    /// Viewport width in pixels, 320-3840. Default 1280.
    pub width: Option<u32>,
    /// Viewport height in pixels, 240-2160. Default 800.
    pub height: Option<u32>,
    /// Managed user to run the browser as. Default: agent.
    pub as_user: Option<String>,
}

pub fn valid_url(url: &str) -> bool {
    (url.starts_with("http://") || url.starts_with("https://"))
        && url.len() <= 2048
        && url.bytes().all(|b| b.is_ascii_graphic())
}

pub fn viewport(width: Option<u32>, height: Option<u32>) -> (u32, u32) {
    (width.unwrap_or(1280).clamp(320, 3840), height.unwrap_or(800).clamp(240, 2160))
}

pub async fn screenshot(ctx: &Ctx, p: ScreenshotParams) -> ToolResult {
    let started = Instant::now();
    if !valid_url(&p.url) {
        return Err("url must be an http:// or https:// URL without spaces".into());
    }
    let (w, h) = viewport(p.width, p.height);
    let run_as = resolve(ctx, p.as_user.as_deref()).await?;
    let found = run_ok(&run_as.argv(&["sh", "-c", FIND_BROWSER]), None).await.unwrap_or_default();
    let browser = String::from_utf8_lossy(&found).lines().next().unwrap_or("").to_string();
    if browser.is_empty() {
        return Err("no Chromium found on the server: install the chromium package".into());
    }
    let file = format!("/tmp/vps-agent-shot-{}-{:x}.png", std::process::id(), super::now());
    let out = run_capture(
        &run_as.argv(&[
            "timeout", "-k", "5", TIMEOUT_SECS, &browser, "--headless", "--disable-gpu",
            "--hide-scrollbars", "--no-first-run", &format!("--window-size={w},{h}"),
            &format!("--screenshot={file}"), &p.url,
        ]),
        None,
    )
    .await?;
    let image = read_bytes(&run_as, &file, MAX_TRANSFER).await;
    let _ = run_capture(&run_as.argv(&["rm", "-f", "--", &file]), None).await;
    audit(
        "screenshot",
        run_as.name(),
        serde_json::json!({"url": p.url, "viewport": [w, h]}),
        out.status.code(),
        started.elapsed().as_millis(),
    );
    let Ok(image) = image else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let last = stderr.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("no output");
        return Err(format!("the browser produced no screenshot (exit {:?}): {last}", out.status.code()));
    };
    let img = prepare_image(&image)?;
    Ok(ToolOutput {
        text: format!("{} ({}x{})", p.url, img.width, img.height),
        image: Some((img.mime, img.base64)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_http_urls_are_accepted() {
        for ok in ["http://127.0.0.1:3000/", "https://example.com/a?b=c#d", "http://localhost"] {
            assert!(valid_url(ok), "{ok}");
        }
        for bad in ["file:///etc/passwd", "javascript:alert(1)", "chrome://version", "ftp://x",
                    "http://a b", "http://a\n--remote-debugging-port=9222", "--screenshot=/etc/x", ""] {
            assert!(!valid_url(bad), "{bad:?}");
        }
    }

    #[test]
    fn viewport_is_defaulted_and_clamped() {
        assert_eq!(viewport(None, None), (1280, 800));
        assert_eq!(viewport(Some(1), Some(1)), (320, 240));
        assert_eq!(viewport(Some(100_000), Some(100_000)), (3840, 2160));
    }
}
