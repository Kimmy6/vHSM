#!/usr/bin/env bash
set -euo pipefail

NODE="${1:-/dev/video0}"
MODE="${2:-1640x1232}"     # 1640x1232 또는 3280x2464
CFA="${3:-BGGR}"           # BGGR 또는 RGGB (센서가 BGGR 고정인 경우가 많음)

echo "== Kill any process holding $NODE =="
if command -v fuser >/dev/null 2>&1; then
  sudo fuser -k "$NODE" || true
fi

echo "== Show media graph BEFORE =="
media-ctl -d /dev/media0 -p || true

echo "== Set sensor(subdev) bus format =="
# 센서 엔티티 이름은 보통 "imx219 10-0010":0 입니다. (media-ctl -p 출력 기준)
if [[ "$CFA" == "BGGR" ]]; then
  BUSFMT="SBGGR10_1X10"
else
  BUSFMT="SRGGB10_1X10"
fi
sudo media-ctl -d /dev/media0 --set-v4l2 "\"imx219 10-0010\":0[fmt:${BUSFMT}/${MODE}]"

echo "== Verify media graph AFTER =="
media-ctl -d /dev/media0 -p | sed -n '/imx219 10-0010/,/entity/p' || true

echo "== Set video node pixel format to match =="
W="${MODE%x*}"; H="${MODE#*x}"
if [[ "$CFA" == "BGGR" ]]; then
  PIXFMT="pBAA"   # packed 10-bit BGGR
else
  PIXFMT="pRAA"   # packed 10-bit RGGB
fi
v4l2-ctl -d "$NODE" --set-fmt-video=width="$W",height="$H",pixelformat="$PIXFMT"

echo "== Get video node format =="
v4l2-ctl -d "$NODE" --get-fmt-video

echo "== Try streaming 10 frames via MMAP =="
set +e
v4l2-ctl -d "$NODE" --stream-mmap=3 --stream-count=10 --stream-to=/tmp/frame.raw --verbose
RC=$?
set -e
if [[ $RC -ne 0 ]]; then
  echo "!! STREAMON failed. Trying half-res fallback (1640x1232) with BGGR..."
  sudo media-ctl -d /dev/media0 --set-v4l2 "\"imx219 10-0010\":0[fmt:SBGGR10_1X10/1640x1232]"
  v4l2-ctl -d "$NODE" --set-fmt-video=width=1640,height=1232,pixelformat=pBAA
  v4l2-ctl -d "$NODE" --get-fmt-video
  v4l2-ctl -d "$NODE" --stream-mmap=3 --stream-count=10 --stream-to=/tmp/frame.raw --verbose
fi

echo "== OK. When streaming works, run the JPEG app accordingly =="
if [[ -f ./raw_cap_to_jpeg ]]; then
  if [[ "$CFA" == "BGGR" ]]; then
    ./raw_cap_to_jpeg "$NODE" "$W" "$H" out.jpg -p BGGR -q 90
  else
    ./raw_cap_to_jpeg "$NODE" "$W" "$H" out.jpg -p RGGB -q 90
  fi
fi
