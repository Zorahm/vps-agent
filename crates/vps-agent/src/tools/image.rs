use super::fs::{read_bytes, resolve_path, MAX_TRANSFER};
use super::{ToolOutput, ToolResult};
use crate::audit::audit;
use crate::ctx::Ctx;
use crate::runas::resolve;
use std::time::Instant;

pub const MAX_SIDE: u32 = 1568;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ViewImageParams {
    /// Absolute path of a PNG, JPEG, GIF or WebP file on the server.
    pub path: String,
    /// Managed user to read as. Default: agent.
    pub as_user: Option<String>,
}

pub struct Prepared {
    pub mime: String,
    pub base64: String,
    pub width: u32,
    pub height: u32,
}

pub fn fit_within(w: u32, h: u32, max_side: u32) -> (u32, u32) {
    let long = w.max(h);
    if long <= max_side {
        return (w, h);
    }
    let scale = |v: u32| ((v as u64 * max_side as u64) / long as u64).max(1) as u32;
    (scale(w), scale(h))
}

pub fn prepare_image(bytes: &[u8]) -> Result<Prepared, String> {
    use base64::Engine;
    let img = image::load_from_memory(bytes).map_err(|e| format!("not a supported image: {e}"))?;
    let (width, height) = fit_within(img.width(), img.height(), MAX_SIDE);
    let img = if (width, height) == (img.width(), img.height()) {
        img
    } else {
        img.resize_exact(width, height, image::imageops::FilterType::Triangle)
    };
    let mut buf = std::io::Cursor::new(Vec::new());
    img.write_to(&mut buf, image::ImageFormat::Png).map_err(|e| e.to_string())?;
    Ok(Prepared {
        mime: "image/png".into(),
        base64: base64::engine::general_purpose::STANDARD.encode(buf.get_ref()),
        width,
        height,
    })
}

pub async fn view_image(ctx: &Ctx, p: ViewImageParams) -> ToolResult {
    let started = Instant::now();
    let run_as = resolve(ctx, p.as_user.as_deref()).await?;
    let real = resolve_path(ctx, &run_as, &p.path).await?;
    let data = read_bytes(&run_as, &real, MAX_TRANSFER).await?;
    let img = prepare_image(&data)?;
    audit("view_image", run_as.name(), serde_json::json!({"path": real}), Some(0), started.elapsed().as_millis());
    Ok(ToolOutput {
        text: format!("{real} ({}x{})", img.width, img.height),
        image: Some((img.mime, img.base64)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_images_keep_their_size() {
        assert_eq!(fit_within(800, 600, 1568), (800, 600));
        assert_eq!(fit_within(1568, 1568, 1568), (1568, 1568));
    }

    #[test]
    fn large_images_scale_by_the_long_side() {
        assert_eq!(fit_within(3136, 1568, 1568), (1568, 784));
        assert_eq!(fit_within(1000, 4000, 1568), (392, 1568));
        assert_eq!(fit_within(10000, 1, 1568), (1568, 1));
    }

    #[test]
    fn prepares_a_png_and_rejects_garbage() {
        let img = image::RgbImage::from_pixel(3000, 10, image::Rgb([1, 2, 3]));
        let mut buf = std::io::Cursor::new(Vec::new());
        img.write_to(&mut buf, image::ImageFormat::Png).unwrap();
        let p = prepare_image(buf.get_ref()).unwrap();
        assert_eq!(p.mime, "image/png");
        assert_eq!((p.width, p.height), (1568, 5));
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(p.base64).unwrap();
        let back = image::load_from_memory(&bytes).unwrap();
        assert_eq!((back.width(), back.height()), (1568, 5));
        assert!(prepare_image(b"not an image").is_err());
    }
}
