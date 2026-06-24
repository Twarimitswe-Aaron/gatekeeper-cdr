<?php

namespace Gatekeeper;

use FFI;
use RuntimeException;

class GatekeeperCdr {
    private static ?FFI $ffi = null;

    private static function init(): void {
        if (self::$ffi !== null) {
            return;
        }

        if (!extension_loaded('ffi')) {
            throw new RuntimeException("Gatekeeper CDR requires the PHP FFI extension to be enabled.");
        }

        $baseDir = dirname(__DIR__);
        
        // Define C header using FFI
        $cdef = <<<CDEF
        typedef struct {
            bool ok;
            uint8_t *data;
            size_t len;
            int32_t error_code;
        } CdrResult;

        int32_t gatekeeper_sniff_format(const uint8_t *raw, size_t len, uint8_t *out_fmt, size_t out_len);
        CdrResult gatekeeper_disarm(const uint8_t *raw, size_t len);
        void gatekeeper_free_result(CdrResult result);
CDEF;

        // Path to the bundled native library
        // In a real environment, we would detect OS/Arch and load accordingly.
        // For this testbed, we load the Linux generic build.
        $libPath = $baseDir . '/bindings/php/lib/linux/libgatekeeper.so';

        if (!file_exists($libPath)) {
            throw new RuntimeException("Gatekeeper native library not found at: " . $libPath);
        }

        self::$ffi = FFI::cdef($cdef, $libPath);
    }

    /**
     * Inspects the raw file bytes to determine its format without fully decoding it.
     * 
     * @param string $payload
     * @return string
     * @throws RuntimeException
     */
    public static function sniffFormat(string $payload): string {
        self::init();
        if (empty($payload)) {
            throw new RuntimeException("Payload is empty");
        }

        $len = strlen($payload);
        $cRaw = FFI::new("uint8_t[$len]");
        FFI::memcpy($cRaw, $payload, $len);

        $outLen = 16;
        $cOutFmt = FFI::new("uint8_t[$outLen]");

        $resultCode = self::$ffi->gatekeeper_sniff_format($cRaw, $len, $cOutFmt, $outLen);

        if ($resultCode !== 0) {
            throw new RuntimeException("Unrecognised file magic or format error (code: $resultCode)");
        }

        return FFI::string($cOutFmt);
    }

    /**
     * Sanitizes the input payload by stripping all metadata and potential exploits.
     * 
     * @param string $payload
     * @return string
     * @throws RuntimeException
     */
    public static function disarm(string $payload): string {
        self::init();
        if (empty($payload)) {
            throw new RuntimeException("Payload is empty");
        }

        $len = strlen($payload);
        $cRaw = FFI::new("uint8_t[$len]");
        FFI::memcpy($cRaw, $payload, $len);

        $result = self::$ffi->gatekeeper_disarm($cRaw, $len);

        if (!$result->ok) {
            $errorCode = $result->error_code;
            self::$ffi->gatekeeper_free_result($result);
            throw new RuntimeException("Gatekeeper CDR failed (error code: $errorCode)");
        }

        $cleanPayload = FFI::string($result->data, $result->len);
        self::$ffi->gatekeeper_free_result($result);

        return $cleanPayload;
    }
}
