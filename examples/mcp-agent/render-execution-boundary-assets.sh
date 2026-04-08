#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$ROOT_DIR/tmp/execution-boundary-frames"
CAST_FILE="$ROOT_DIR/demo-execution-boundary.cast"
SVG_FILE="$ROOT_DIR/demo-execution-boundary.svg"
MP4_FILE="$ROOT_DIR/demo-execution-boundary.mp4"
GIF_FILE="$ROOT_DIR/demo-execution-boundary.gif"

mkdir -p "$TMP_DIR"
rm -f "$TMP_DIR"/*

node "$ROOT_DIR/examples/mcp-agent/generate-execution-boundary-cast.mjs"

svg-term --in "$CAST_FILE" --out "$SVG_FILE" --window --no-cursor

times=(
  500
  1600
  2300
  3000
  3900
  5100
  6500
  7900
  9100
  10500
  11500
  12700
)

durations=(
  1.1
  0.7
  0.7
  0.9
  1.2
  1.4
  1.4
  1.2
  1.4
  1.0
  1.2
  1.6
)

concat_file="$TMP_DIR/frames.txt"
: > "$concat_file"

for i in "${!times[@]}"; do
  frame_name=$(printf 'frame-%03d' "$i")
  frame_svg="$TMP_DIR/$frame_name.svg"
  frame_png="$TMP_DIR/$frame_name.png"

  svg-term --in "$CAST_FILE" --at "${times[$i]}" --out "$frame_svg" --window --no-cursor
  ffmpeg -y -loglevel error -i "$frame_svg" "$frame_png"

  {
    printf "file '%s'\n" "$frame_png"
    printf "duration %s\n" "${durations[$i]}"
  } >> "$concat_file"
done

last_png="$TMP_DIR/$(printf 'frame-%03d' "$(( ${#times[@]} - 1 ))").png"
printf "file '%s'\n" "$last_png" >> "$concat_file"

ffmpeg \
  -y \
  -loglevel error \
  -f concat \
  -safe 0 \
  -i "$concat_file" \
  -vf "fps=20,scale=1200:-2:flags=lanczos,format=yuv420p" \
  -movflags +faststart \
  "$MP4_FILE"

ffmpeg \
  -y \
  -loglevel error \
  -f concat \
  -safe 0 \
  -i "$concat_file" \
  -vf "fps=8,scale=640:-1:flags=lanczos,split[s0][s1];[s0]palettegen=stats_mode=diff[p];[s1][p]paletteuse=dither=bayer" \
  "$GIF_FILE"

echo "Rendered:"
echo "  $CAST_FILE"
echo "  $SVG_FILE"
echo "  $MP4_FILE"
echo "  $GIF_FILE"
