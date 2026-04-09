#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$ROOT_DIR/tmp/delegation-frames"
CAST_FILE="$ROOT_DIR/examples/demo-delegation.cast"
SVG_FILE="$ROOT_DIR/demo-delegation.svg"
MP4_FILE="$ROOT_DIR/demo-delegation.mp4"
GIF_FILE="$ROOT_DIR/demo-delegation.gif"

mkdir -p "$TMP_DIR"
rm -f "$TMP_DIR"/*

# Step 1: Generate .cast if not exists
if [ ! -f "$CAST_FILE" ]; then
  echo "Generating .cast file..."
  node "$ROOT_DIR/examples/demo-delegation.mjs"
fi

# Step 2: Generate full SVG
echo "Generating SVG..."
svg-term --in "$CAST_FILE" --out "$SVG_FILE" --window --no-cursor --width 100 --height 36

# Step 3: Extract keyframes at specific timestamps (ms)
# Each timestamp corresponds to a key moment in the demo
times=(
  500    # title screen
  3000   # identity generation
  5000   # alice created
  7000   # deploy-bot created
  9000   # delegation token heading
  12000  # delegation command
  16000  # token JSON output
  19000  # verify token
  21000  # sign with chain heading
  24000  # sign command
  28000  # v4 receipt JSON
  32000  # verify authorized heading
  35000  # verify result
  38000  # out-of-scope heading
  41000  # rejection error
  44000  # audit trail
  48000  # dashboard
  53000  # closing message
)

durations=(
  2.5   # title
  2.0   # identity heading
  1.5   # alice
  2.0   # deploy-bot
  1.5   # delegation heading
  3.0   # delegation command
  3.0   # token JSON
  2.0   # verify
  2.0   # sign heading
  3.0   # sign command
  3.5   # v4 receipt
  2.0   # verify heading
  3.0   # verify result
  2.0   # out-of-scope heading
  3.0   # rejection
  2.5   # audit
  3.5   # dashboard
  3.0   # closing
)

concat_file="$TMP_DIR/frames.txt"
: > "$concat_file"

echo "Extracting ${#times[@]} keyframes..."

for i in "${!times[@]}"; do
  frame_name=$(printf 'frame-%03d' "$i")
  frame_svg="$TMP_DIR/$frame_name.svg"
  frame_png="$TMP_DIR/$frame_name.png"

  svg-term --in "$CAST_FILE" --at "${times[$i]}" --out "$frame_svg" --window --no-cursor --width 100 --height 36
  ffmpeg -y -loglevel error -i "$frame_svg" "$frame_png"

  {
    printf "file '%s'\n" "$frame_png"
    printf "duration %s\n" "${durations[$i]}"
  } >> "$concat_file"
done

# Repeat last frame (ffmpeg concat requirement)
last_png="$TMP_DIR/$(printf 'frame-%03d' "$(( ${#times[@]} - 1 ))").png"
printf "file '%s'\n" "$last_png" >> "$concat_file"

# Step 4: Generate MP4
echo "Rendering MP4..."
ffmpeg \
  -y \
  -loglevel error \
  -f concat \
  -safe 0 \
  -i "$concat_file" \
  -vf "fps=20,scale=1200:-2:flags=lanczos,format=yuv420p" \
  -movflags +faststart \
  "$MP4_FILE"

# Step 5: Generate GIF
echo "Rendering GIF..."
ffmpeg \
  -y \
  -loglevel error \
  -f concat \
  -safe 0 \
  -i "$concat_file" \
  -vf "fps=8,scale=640:-1:flags=lanczos,split[s0][s1];[s0]palettegen=stats_mode=diff[p];[s1][p]paletteuse=dither=bayer" \
  "$GIF_FILE"

echo ""
echo "Rendered:"
echo "  $CAST_FILE  ($(du -h "$CAST_FILE" | cut -f1))"
echo "  $SVG_FILE   ($(du -h "$SVG_FILE" | cut -f1))"
echo "  $MP4_FILE   ($(du -h "$MP4_FILE" | cut -f1))"
echo "  $GIF_FILE   ($(du -h "$GIF_FILE" | cut -f1))"
