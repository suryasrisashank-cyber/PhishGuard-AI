"""
PhishGuard AI 2.0 — Screenshot Analysis Service
=================================================
IMPORTANT: This service performs heuristic image analysis only.
It does NOT use AI, machine learning, or visual recognition.
All analysis is based on image metadata and basic pixel statistics.
Labels are honest and clearly marked as heuristic-only.
"""
from typing import Any
from PIL import Image
import io


def analyze_screenshot(file_bytes: bytes) -> dict[str, Any]:
    """
    Heuristic image analysis of uploaded screenshots.
    
    Returns image metadata and basic heuristic observations.
    Does NOT claim AI detection, visual recognition, or true content analysis.
    Results must NOT be presented as AI-powered threat detection.
    """
    try:
        image = Image.open(io.BytesIO(file_bytes))
        width, height = image.size
        mode = image.mode
        file_size_kb = round(len(file_bytes) / 1024, 1)
        format_name = image.format or "Unknown"

        # Basic color analysis (honest — just pixel statistics)
        try:
            import numpy as np
            pixels = np.array(image.convert("RGB"))
            avg_brightness = float(pixels.mean())
            dark_ratio = float((pixels < 50).sum() / pixels.size)
            high_contrast = dark_ratio > 0.4 or dark_ratio < 0.1
        except ImportError:
            avg_brightness = None
            dark_ratio = None
            high_contrast = False

        indicators = [
            {
                "name": "Image Format",
                "ioc_type": "FILE",
                "ioc_value": format_name,
                "severity": "INFORMATIONAL",
                "passed": True,
                "explanation": f"Image format: {format_name}. No format-based risk factors detected.",
                "score_impact": 0.0,
            },
            {
                "name": "Image Dimensions",
                "ioc_type": "FILE",
                "ioc_value": f"{width}x{height} pixels",
                "severity": "INFORMATIONAL",
                "passed": True,
                "explanation": f"Screenshot dimensions are {width}x{height} pixels ({width*height:,} total pixels).",
                "score_impact": 0.0,
            },
            {
                "name": "File Size",
                "ioc_type": "FILE",
                "ioc_value": f"{file_size_kb} KB",
                "severity": "INFORMATIONAL",
                "passed": True,
                "explanation": f"Image file size is {file_size_kb} KB.",
                "score_impact": 0.0,
            },
        ]

        if avg_brightness is not None:
            indicators.append({
                "name": "Average Pixel Brightness",
                "ioc_type": "FILE",
                "ioc_value": f"{avg_brightness:.1f} / 255",
                "severity": "INFORMATIONAL",
                "passed": True,
                "explanation": f"Average pixel brightness: {avg_brightness:.1f} (scale 0-255). This is image metadata only — brightness is not a phishing indicator.",
                "score_impact": 0.0,
            })

        return {
            "analysis_type": "Heuristic Image Analysis",
            "analysis_disclaimer": (
                "This analysis is based on image metadata and basic pixel statistics only. "
                "It does NOT use AI, machine learning, or visual content recognition. "
                "PhishGuard AI 2.0 cannot detect login pages, brand logos, or form elements from screenshots. "
                "For website content analysis, use the Website Analyzer with the direct URL."
            ),
            "image_info": {
                "format": format_name,
                "dimensions": f"{width}x{height}",
                "width": width,
                "height": height,
                "mode": mode,
                "file_size_kb": file_size_kb,
            },
            "risk_score": 0.0,
            "confidence_score": None,
            "verdict": "Unknown",
            "severity": "INFORMATIONAL",
            "summary": f"Heuristic image analysis complete. {width}x{height}px {format_name} image, {file_size_kb}KB. No content-based analysis available without AI/OCR integration.",
            "indicators": indicators,
            "mitre_techniques": [],
            "analyst_actions": [
                "For proper phishing detection, use the Website Analyzer with the page URL instead of a screenshot.",
                "If this screenshot shows a suspected phishing page, analyze the URL directly.",
                "OCR text extraction is not implemented — visible URLs in the image must be manually copied for analysis.",
            ],
            "detection_engine_version": "2.0.0",
        }

    except Exception as exc:
        return {
            "analysis_type": "Heuristic Image Analysis",
            "risk_score": 0.0,
            "confidence_score": None,
            "verdict": "Unknown",
            "severity": "INFORMATIONAL",
            "summary": f"Screenshot analysis failed: {type(exc).__name__}: {exc}",
            "indicators": [],
            "mitre_techniques": [],
            "analyst_actions": ["Verify the uploaded file is a valid image (PNG, JPG, WEBP, BMP)."],
            "detection_engine_version": "2.0.0",
        }
