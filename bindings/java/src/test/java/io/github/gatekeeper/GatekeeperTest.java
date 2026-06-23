package io.github.gatekeeper;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class GatekeeperTest {

    @Test
    void testSniffFormatWithNullPayload() {
        assertThrows(RuntimeException.class, () -> GatekeeperCdr.sniffFormat(null));
    }

    @Test
    void testSniffFormatWithUnknownFormat() {
        byte[] payload = "this_is_some_random_string_that_is_not_an_image".getBytes();
        RuntimeException thrown = assertThrows(RuntimeException.class, () -> GatekeeperCdr.sniffFormat(payload));
        assertTrue(thrown.getMessage().contains("unrecognised file magic"));
    }

    @Test
    void testSniffFormatWithValidPng() {
        // Construct a structural PNG header
        byte[] pngSig = {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
        byte[] chunkLen = {0x00, 0x00, 0x00, 0x0D};
        byte[] chunkType = "IHDR".getBytes();

        byte[] validPngHeader = new byte[pngSig.length + chunkLen.length + chunkType.length];
        System.arraycopy(pngSig, 0, validPngHeader, 0, pngSig.length);
        System.arraycopy(chunkLen, 0, validPngHeader, pngSig.length, chunkLen.length);
        System.arraycopy(chunkType, 0, validPngHeader, pngSig.length + chunkLen.length, chunkType.length);

        FileFormat format = GatekeeperCdr.sniffFormat(validPngHeader);
        assertEquals(FileFormat.PNG, format);
    }

    @Test
    void testDisarmWithInvalidPayload() {
        byte[] payload = "invalid_image_payload".getBytes();
        RuntimeException thrown = assertThrows(RuntimeException.class, () -> GatekeeperCdr.disarm(payload));
        assertTrue(thrown.getMessage().contains("CDR sanitization failed"));
    }
}
