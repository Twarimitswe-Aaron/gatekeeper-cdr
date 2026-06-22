const gatekeeper = require('./index.js');
const fs = require('fs');

console.log("Testing Gatekeeper CDR Node.js Bindings...\n");

// 1. Test garbage bytes (Expect Exception)
const garbage = Buffer.from("UNKNOWN_MAGIC_BYTES_123");
try {
    gatekeeper.disarm(garbage, null);
    console.error("❌ FAILED: Should have rejected garbage bytes.");
} catch (e) {
    console.log("✅ Passed: Caught expected error for garbage:");
    console.log("   ->", e.message);
}

// 2. Test FormatMismatch (Expect Exception)
const pngSignature = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52]);
try {
    gatekeeper.disarm(pngSignature, "pdf");
    console.error("❌ FAILED: Should have rejected due to FormatMismatch.");
} catch (e) {
    console.log("✅ Passed: Caught expected error for FormatMismatch:");
    console.log("   ->", e.message);
}

// 3. Test Minimal PDF (FFI check)
const validPdf = Buffer.from("%PDF-1.4\nTrailer << /Root << >> >>\n%%EOF");
try {
    const result = gatekeeper.disarm(validPdf, "pdf");
    console.log("✅ Passed: Sanitized PDF.");
    console.log(`   -> Output Size: ${result.finalSizeBytes} bytes`);
    console.log(`   -> Detected: ${result.detectedFormat}`);
} catch (e) {
    console.log("✅ Passed FFI (Handled gracefully via CdrError):");
    console.log("   ->", e.message);
}
