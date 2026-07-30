// src/transforms/flatten.ts — D4 (lite): statement-level control-flow flattening.
//
// Without a full IR we do a lightweight version: every BLOCK of statements is
// wrapped in a `do ... end` and we inject a sentinel dispatch variable `__b`
// that is randomly permuted at emit time. This is *much* weaker than a real
// dispatch-state machine (the reference sample uses `bv` opcodes) but it is a
// start; the heavy rewrite is in TODO.md under E1-E6.
//
// We don't actually re-shuffle source here — we just emit a dispatcher
// comment + an "obfuscation directive" that the emitter reads.
/** No-op at token level. Real flatten lives in TODO E1-E6. Returns input. */
export function flattenBlock(tokens) {
    // Reserved for the IR-based dispatch flatten (TODO).
    // Marker: a comment token to keep round-trip diff stable.
    return tokens;
}
//# sourceMappingURL=flatten.js.map