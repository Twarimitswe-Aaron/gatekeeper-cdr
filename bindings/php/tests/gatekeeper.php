<?php
// Make sure the extension is loaded, e.g. via:
// php -d extension=../../target/debug/libgatekeeper_php.so tests/gatekeeper.php

echo "Testing gatekeeper_sniff_format()...\n";

$png_sig = "\x89PNG\r\n\x1a\n";
$chunk_len = "\x00\x00\x00\x0D";
$chunk_type = "IHDR";
$valid_png_header = $png_sig . $chunk_len . $chunk_type;

try {
    $format = gatekeeper_sniff_format($valid_png_header);
    if ($format === "Png") {
        echo "✅ PNG sniffer passed.\n";
    } else {
        echo "❌ Expected 'Png', got '$format'\n";
    }
} catch (Exception $e) {
    echo "❌ Sniffer threw exception: " . $e->getMessage() . "\n";
}

try {
    gatekeeper_sniff_format("invalid_random_bytes_that_are_not_a_known_format");
    echo "❌ Sniffer failed to reject invalid format.\n";
} catch (Exception $e) {
    if (strpos($e->getMessage(), "unrecognised file magic") !== false || strpos($e->getMessage(), "Unknown format") !== false) {
        echo "✅ Invalid format properly rejected.\n";
    } else {
        echo "❌ Unexpected exception message: " . $e->getMessage() . "\n";
    }
}

echo "Testing gatekeeper_disarm()...\n";

try {
    gatekeeper_disarm("short");
    echo "❌ Disarm failed to reject short payload.\n";
} catch (Exception $e) {
    echo "✅ Disarm properly rejected invalid payload.\n";
}

echo "\nAll tests completed.\n";
