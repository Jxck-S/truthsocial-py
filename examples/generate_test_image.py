from __future__ import annotations

import struct
import zlib
from pathlib import Path

WIDTH = 640
HEIGHT = 360
OUTPUT = Path(__file__).with_name("truthpy-test.png")

FONT = {
    "A": ("01110", "10001", "10001", "11111", "10001", "10001", "10001"),
    "D": ("11110", "10001", "10001", "10001", "10001", "10001", "11110"),
    "E": ("11111", "10000", "10000", "11110", "10000", "10000", "11111"),
    "H": ("10001", "10001", "10001", "11111", "10001", "10001", "10001"),
    "I": ("11111", "00100", "00100", "00100", "00100", "00100", "11111"),
    "M": ("10001", "11011", "10101", "10101", "10001", "10001", "10001"),
    "P": ("11110", "10001", "10001", "11110", "10000", "10000", "10000"),
    "R": ("11110", "10001", "10001", "11110", "10100", "10010", "10001"),
    "S": ("01111", "10000", "10000", "01110", "00001", "00001", "11110"),
    "T": ("11111", "00100", "00100", "00100", "00100", "00100", "00100"),
    "U": ("10001", "10001", "10001", "10001", "10001", "10001", "01110"),
    "Y": ("10001", "10001", "01010", "00100", "00100", "00100", "00100"),
}


def set_pixel(
    pixels: bytearray,
    x: int,
    y: int,
    color: tuple[int, int, int],
) -> None:
    if 0 <= x < WIDTH and 0 <= y < HEIGHT:
        offset = (y * WIDTH + x) * 3
        pixels[offset : offset + 3] = bytes(color)


def fill_rect(
    pixels: bytearray,
    x: int,
    y: int,
    width: int,
    height: int,
    color: tuple[int, int, int],
) -> None:
    for pixel_y in range(y, y + height):
        for pixel_x in range(x, x + width):
            set_pixel(pixels, pixel_x, pixel_y, color)


def draw_text(
    pixels: bytearray,
    text: str,
    x: int,
    y: int,
    scale: int,
    color: tuple[int, int, int],
) -> None:
    cursor = x
    for character in text:
        if character == " ":
            cursor += 4 * scale
            continue
        glyph = FONT[character]
        for row, bits in enumerate(glyph):
            for column, bit in enumerate(bits):
                if bit == "1":
                    fill_rect(
                        pixels,
                        cursor + column * scale,
                        y + row * scale,
                        scale,
                        scale,
                        color,
                    )
        cursor += 6 * scale


def png_chunk(kind: bytes, data: bytes) -> bytes:
    checksum = zlib.crc32(kind + data) & 0xFFFFFFFF
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", checksum)
    )


def generate(path: Path = OUTPUT) -> Path:
    pixels = bytearray(WIDTH * HEIGHT * 3)
    for y in range(HEIGHT):
        for x in range(WIDTH):
            offset = (y * WIDTH + x) * 3
            pixels[offset] = 15 + (x * 30 // WIDTH)
            pixels[offset + 1] = 24 + (y * 34 // HEIGHT)
            pixels[offset + 2] = 46 + ((x + y) * 35 // (WIDTH + HEIGHT))

    fill_rect(pixels, 32, 32, WIDTH - 64, HEIGHT - 64, (23, 37, 67))
    fill_rect(pixels, 32, 32, WIDTH - 64, 8, (226, 48, 75))
    fill_rect(pixels, 32, HEIGHT - 40, WIDTH - 64, 8, (226, 48, 75))

    draw_text(pixels, "TRUTHPY", 92, 92, 12, (8, 13, 27))
    draw_text(pixels, "TRUTHPY", 86, 86, 12, (245, 247, 255))
    draw_text(pixels, "MEDIA TEST", 142, 232, 6, (226, 48, 75))

    scanlines = bytearray()
    stride = WIDTH * 3
    for y in range(HEIGHT):
        scanlines.append(0)
        start = y * stride
        scanlines.extend(pixels[start : start + stride])

    png = bytearray(b"\x89PNG\r\n\x1a\n")
    png.extend(
        png_chunk(
            b"IHDR",
            struct.pack(">IIBBBBB", WIDTH, HEIGHT, 8, 2, 0, 0, 0),
        )
    )
    png.extend(png_chunk(b"tEXt", b"Software\x00truthpy test generator"))
    png.extend(png_chunk(b"IDAT", zlib.compress(bytes(scanlines), level=9)))
    png.extend(png_chunk(b"IEND", b""))
    path.write_bytes(png)
    return path


if __name__ == "__main__":
    output = generate()
    print(f"Generated {output} ({output.stat().st_size} bytes)")
