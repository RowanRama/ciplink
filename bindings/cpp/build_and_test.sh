#!/usr/bin/env bash
# Builds the ciplink library (crates/ciplink-ffi), regenerates ciplink.h if cbindgen is installed, compiles the C++
# tests and example, and runs the tests against two ciplink-sim servers (Logix and SLC) over TCP.
#   bindings/cpp/build_and_test.sh                  debug build, compiled with $CXX (default g++)
#   PROFILE=release bindings/cpp/build_and_test.sh
#   BUILD=cmake bindings/cpp/build_and_test.sh      compiled through CMakeLists.txt (e.g. MSVC on Windows)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
profile="${PROFILE:-debug}"
build="${BUILD:-cxx}"
cxx="${CXX:-g++}"
out="$here/build"
mkdir -p "$out"

cd "$repo"
flag=""
[ "$profile" = release ] && flag="--release"
cargo build $flag -p ciplink-ffi -p ciplink-sim
if command -v cbindgen >/dev/null; then
    (cd crates/ciplink-ffi && cbindgen --config cbindgen.toml --crate ciplink-ffi --output include/ciplink.h)
fi

target="${CARGO_TARGET_DIR:-$repo/target}/$profile"
case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*) exe=.exe ;;
    *) exe="" ;;
esac

if [ "$build" = cmake ]; then
    config=Debug
    [ "$profile" = release ] && config=Release
    cmake -S "$here" -B "$out/cmake" -DCIPLINK_LIB_DIR="$target" -DCMAKE_BUILD_TYPE="$config"
    cmake --build "$out/cmake" --config "$config"
    # single-config generators write to the build folder, multi-config ones (Visual Studio) to a per-config folder
    test_exe="$(find "$out/cmake" -name "test_ciplink$exe" -type f | head -1)"
else
    inc=(-I "$here/include" -I "$repo/crates/ciplink-ffi/include")
    for src in tests/test_ciplink examples/example; do
        "$cxx" -std=c++17 -Wall -Wextra -O1 "${inc[@]}" "$here/$src.cpp" -L "$target" -lciplink \
            -Wl,-rpath,"$target" -o "$out/$(basename "$src")$exe"
    done
    if [ -n "$exe" ]; then cp "$target/ciplink.dll" "$out/"; fi
    test_exe="$out/test_ciplink$exe"
fi

# start the simulators in this shell (so they can be killed on exit), then read their ports from their logs
pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true' EXIT
for sim in logix:example_controller.json slc:example_slc.json; do
    "$target/ciplink-sim$exe" --config "$repo/tools/sim/${sim#*:}" --port 0 >"$out/sim_${sim%%:*}.log" 2>&1 &
    pids+=($!)
done
port_of() {
    local log="$out/sim_$1.log"
    for _ in $(seq 100); do
        if grep -q "listening on" "$log"; then
            sed -n 's/.*listening on [0-9.]*:\([0-9]*\).*/\1/p' "$log" | head -1
            return
        fi
        sleep 0.1
    done
    echo "simulator $1 did not start" >&2
    cat "$log" >&2
    exit 1
}
logix_port="$(port_of logix)"
slc_port="$(port_of slc)"
"$test_exe" "$logix_port" "$slc_port" "$repo/crates/ciplink/tests/fixtures/logix_descriptions.json"
