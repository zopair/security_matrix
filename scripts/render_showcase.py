#!/usr/bin/env python3
"""Render a narrated 720p project overview with local, no-cost tools."""

import json
import subprocess
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "video/showcase.json").read_text(encoding="utf-8"))
OUTPUT = ROOT / "assets/marketing"
WORK = ROOT / ".showcase-build"
OUTPUT.mkdir(parents=True, exist_ok=True)
WORK.mkdir(parents=True, exist_ok=True)

WIDTH, HEIGHT = 1280, 720
FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
BOLD_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
ACCENT = tuple(CONFIG.get("accent", [90, 160, 240]))


def run(command):
    subprocess.run(
        command,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )


def render_card(title, body, index, total, path, end_card=False):
    image = Image.new("RGB", (WIDTH, HEIGHT), (9, 17, 32))
    draw = ImageDraw.Draw(image, "RGBA")

    for x in range(0, WIDTH, 64):
        draw.line((x, 0, x, HEIGHT), fill=(100, 130, 170, 18))
    for y in range(0, HEIGHT, 64):
        draw.line((0, y, WIDTH, y), fill=(100, 130, 170, 16))

    draw.ellipse(
        (900, -240, 1480, 340),
        outline=(*ACCENT, 75),
        width=3,
    )
    draw.ellipse(
        (1010, -140, 1390, 240),
        fill=(*ACCENT, 16),
        outline=(*ACCENT, 50),
        width=2,
    )
    draw.rounded_rectangle(
        (72, 58, 650, 104),
        18,
        fill=(*ACCENT, 30),
        outline=(*ACCENT, 110),
    )
    draw.text(
        (92, 70),
        CONFIG["tag"].upper(),
        font=ImageFont.truetype(BOLD_PATH, 16),
        fill=(225, 235, 248),
    )
    draw.text(
        (72, 150),
        CONFIG["name"].upper(),
        font=ImageFont.truetype(BOLD_PATH, 31),
        fill=(*ACCENT, 255),
    )

    if end_card:
        title = "EXPLORE THE PROJECT ON GITHUB"
        body = CONFIG["url"]
    else:
        draw.text(
            (1120, 70),
            f"{index:02d} / {total:02d}",
            font=ImageFont.truetype(BOLD_PATH, 20),
            fill=(175, 193, 215),
        )

    y_position = 250
    for line in textwrap.wrap(title.upper(), 34):
        draw.text(
            (72, y_position),
            line,
            font=ImageFont.truetype(BOLD_PATH, 48),
            fill=(248, 250, 253),
        )
        y_position += 62

    draw.rounded_rectangle(
        (72, 500, 1208, 630),
        18,
        fill=(7, 15, 29, 235),
        outline=(120, 145, 180, 70),
    )
    body_width = 90 if end_card else 105
    for line_index, line in enumerate(textwrap.wrap(body, body_width)[:3]):
        draw.text(
            (100, 526 + line_index * 31),
            line,
            font=ImageFont.truetype(FONT_PATH, 21),
            fill=(211, 223, 239),
        )

    if end_card:
        draw.text(
            (100, 585),
            "Aly Hussein Zopair  |  Project Overview",
            font=ImageFont.truetype(FONT_PATH, 17),
            fill=(150, 170, 198),
        )
    else:
        draw.rounded_rectangle(
            (72, 665, 1208, 672),
            4,
            fill=(90, 110, 140, 55),
        )
        progress_end = 72 + int(1136 * index / total)
        draw.rounded_rectangle(
            (72, 665, progress_end, 672),
            4,
            fill=(*ACCENT, 255),
        )

    image.save(path)


clips = []
scenes = CONFIG["scenes"]

for index, scene in enumerate(scenes, 1):
    image_path = WORK / f"scene-{index}.png"
    audio_path = WORK / f"voice-{index}.wav"
    clip_path = WORK / f"clip-{index}.mp4"

    render_card(
        scene["title"],
        scene["narration"],
        index,
        len(scenes),
        image_path,
    )
    run(
        [
            "espeak",
            "-v",
            "en-us+f3",
            "-s",
            "142",
            "-p",
            "43",
            "-a",
            "175",
            "-w",
            str(audio_path),
            scene["narration"],
        ]
    )

    duration = float(
        subprocess.check_output(
            [
                "ffprobe",
                "-v",
                "error",
                "-show_entries",
                "format=duration",
                "-of",
                "csv=p=0",
                str(audio_path),
            ]
        ).decode().strip()
    ) + 0.8

    run(
        [
            "ffmpeg",
            "-y",
            "-loop",
            "1",
            "-i",
            str(image_path),
            "-i",
            str(audio_path),
            "-t",
            f"{duration:.2f}",
            "-vf",
            "scale=1280:720,format=yuv420p",
            "-r",
            "24",
            "-c:v",
            "libx264",
            "-preset",
            "ultrafast",
            "-b:v",
            "520k",
            "-c:a",
            "aac",
            "-b:a",
            "96k",
            "-shortest",
            str(clip_path),
        ]
    )
    clips.append(clip_path)

end_image = WORK / "end-card.png"
end_clip = WORK / "end-card.mp4"
render_card("", "", len(scenes), len(scenes), end_image, end_card=True)
run(
    [
        "ffmpeg",
        "-y",
        "-loop",
        "1",
        "-i",
        str(end_image),
        "-f",
        "lavfi",
        "-i",
        "anullsrc=channel_layout=stereo:sample_rate=44100",
        "-t",
        "7",
        "-vf",
        "scale=1280:720,format=yuv420p",
        "-r",
        "24",
        "-c:v",
        "libx264",
        "-preset",
        "ultrafast",
        "-b:v",
        "520k",
        "-c:a",
        "aac",
        "-b:a",
        "96k",
        "-shortest",
        str(end_clip),
    ]
)
clips.append(end_clip)

concat_list = WORK / "concat.txt"
concat_list.write_text(
    "\n".join(f"file '{clip.as_posix()}'" for clip in clips) + "\n",
    encoding="utf-8",
)
target = OUTPUT / "project-overview.mp4"

run(
    [
        "ffmpeg",
        "-y",
        "-f",
        "concat",
        "-safe",
        "0",
        "-i",
        str(concat_list),
        "-c:v",
        "libx264",
        "-preset",
        "ultrafast",
        "-b:v",
        "520k",
        "-maxrate",
        "700k",
        "-bufsize",
        "1400k",
        "-pix_fmt",
        "yuv420p",
        "-c:a",
        "aac",
        "-b:a",
        "96k",
        "-movflags",
        "+faststart",
        str(target),
    ]
)

print(f"Rendered {target} ({target.stat().st_size} bytes)")
