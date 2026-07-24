from typing import Any
from PIL import Image
import io
import numpy as np


def analyze_screenshot(file_bytes: bytes) -> dict[str, Any]:
    try:
        image = Image.open(io.BytesIO(file_bytes))
        width, height = image.size
        pixels = np.array(image)
        avg_brightness = float(pixels.mean())
        suspicious_ui = "login" in image.mode.lower()
        return {
            "confidence_score": round(min(max(avg_brightness / 255 * 100, 0), 100), 2),
            "verdict": "Suspicious" if suspicious_ui else "Safe",
            "summary": f"Screenshot resolution {width}x{height}, average brightness {avg_brightness:.2f}",
        }
    except Exception as exc:
        return {"confidence_score": 0.0, "verdict": "Unknown", "summary": f"Screenshot analysis failed: {exc}"}
