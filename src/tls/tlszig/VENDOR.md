# Vendored: ianic/tls.zig

Source: https://github.com/ianic/tls.zig
Commit: d633a0f276294f84836ab9a81ba79b805790b2c8
Vendored: 2026-07-22
License: MIT (see LICENSE in this directory)

## Why vendored (not a build.zig.zon dependency)

tls.zig's own `build.zig` uses a 0.17-dev API (`addPassthruArgs`) and its
`build.zig.zon` declares `minimum_zig_version = 0.17.0-dev`, so `b.dependency("tls")`
cannot resolve it on Zig 0.16 (it would compile tls.zig's build.zig). tls.zig's
`src/` itself compiles cleanly on 0.16, so we consume the source directly as a
local module (`src/tls/tlszig/root.zig`), wired in httpx's build.zig as the "tls"
module. This is the "consume src/ as a module" option from the HTTP/2 design.

## Local patches (kept minimal)

This tree is a verbatim copy of upstream `src/` at the commit above, with ONE local edit
required to compile on Zig 0.16:

- `record.zig`: `info.mode == .exhaustive` → `info.is_exhaustive`. On Zig 0.16
  `std.builtin.Type.Enum` exposes `is_exhaustive: bool`; upstream targets 0.17-dev where the
  field was renamed to `mode: Mode`. Search for `vendor 0.16-compat` to find it.

## Updating

Re-copy `src/` from the pinned commit above (or a newer one), keeping this file's provenance
current, then re-apply the local patch listed above (until upstream supports 0.16 directly).
