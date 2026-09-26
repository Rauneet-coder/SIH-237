"""
Robustness Attack & Transformation Simulator
Simulates real-world leak conditions: JPEG compression, Gaussian blur,
cropping, resizing, and optical screen recapture.
"""

import io
from PIL import Image, ImageFilter, ImageEnhance
import numpy as np

def apply_transformations(image_bytes: bytes, transforms: list[str]) -> bytes:
    """
    Apply a chain of transformation attacks to an image buffer.
    Available transforms: 'jpeg_compress', 'blur', 'crop_margins', 'add_noise', 'camera_sim'
    """
    image = Image.open(io.BytesIO(image_bytes)).convert("RGB")

    for t in transforms:
        if t == "jpeg_compress":
            buffer = io.BytesIO()
            image.save(buffer, format="JPEG", quality=60)
            buffer.seek(0)
            image = Image.open(buffer)

        elif t == "blur":
            image = image.filter(ImageFilter.GaussianBlur(radius=1.2))

        elif t == "crop_margins":
            w, h = image.size
            # Crop 5% margins from edges
            image = image.crop((int(w * 0.05), int(h * 0.05), int(w * 0.95), int(h * 0.95)))

        elif t == "add_noise":
            arr = np.array(image).astype(np.float32)
            noise = np.random.normal(0, 15, arr.shape)
            noisy_arr = np.clip(arr + noise, 0, 255).astype(np.uint8)
            image = Image.fromarray(noisy_arr)

        elif t == "camera_sim":
            # Simulate optical photo: slight contrast shift, minor blur, and JPEG compression
            enhancer = ImageEnhance.Contrast(image)
            image = enhancer.enhance(1.1)
            image = image.filter(ImageFilter.GaussianBlur(radius=0.8))
            buffer = io.BytesIO()
            image.save(buffer, format="JPEG", quality=75)
            buffer.seek(0)
            image = Image.open(buffer)

    out_buffer = io.BytesIO()
    image.save(out_buffer, format="PNG")
    return out_buffer.getvalue()
