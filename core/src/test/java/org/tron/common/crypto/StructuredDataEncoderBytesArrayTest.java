package org.tron.common.crypto;

import org.junit.Assert;
import org.junit.Test;

/**
 * Regression tests for S-03: a bytesN[] element whose reflective construction
 * failed used to be silently swallowed, contributing zero bytes to the array
 * concatenation — so [invalid, X] and [X] hashed to the same value.
 */
public class StructuredDataEncoderBytesArrayTest {

    private static final String VALID_ITEM =
            "0x1111111111111111111111111111111111111111111111111111111111111111";
    // 31 bytes — one byte short of the declared bytes32 width.
    private static final String SHORT_ITEM =
            "0x11111111111111111111111111111111111111111111111111111111111111";

    private static String messageJson(String... items) {
        StringBuilder array = new StringBuilder();
        for (int i = 0; i < items.length; i++) {
            if (i > 0) {
                array.append(',');
            }
            array.append('"').append(items[i]).append('"');
        }
        return "{"
                + "\"types\":{"
                + "\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"}],"
                + "\"Payload\":[{\"name\":\"items\",\"type\":\"bytes32[]\"}]"
                + "},"
                + "\"primaryType\":\"Payload\","
                + "\"domain\":{\"name\":\"Test\"},"
                + "\"message\":{\"items\":[" + array + "]}"
                + "}";
    }

    @Test
    public void validBytes32Array_hashesSuccessfully() throws Exception {
        byte[] hash = new StructuredDataEncoder(messageJson(VALID_ITEM)).hashMessage();
        Assert.assertEquals(32, hash.length);
    }

    @Test
    public void shortBytes32Element_isRejectedInsteadOfCollapsing() throws Exception {
        StructuredDataEncoder encoder =
                new StructuredDataEncoder(messageJson(SHORT_ITEM, VALID_ITEM));
        try {
            encoder.hashMessage();
            Assert.fail("Expected IllegalArgumentException for 31-byte bytes32 element");
        } catch (IllegalArgumentException expected) {
            // [SHORT_ITEM, VALID_ITEM] must be rejected, never hash like [VALID_ITEM]
        }
    }

    @Test
    public void oversizedBytes32Element_isRejected() throws Exception {
        String oversized = VALID_ITEM + "22"; // 33 bytes
        StructuredDataEncoder encoder = new StructuredDataEncoder(messageJson(oversized));
        try {
            encoder.hashMessage();
            Assert.fail("Expected IllegalArgumentException for 33-byte bytes32 element");
        } catch (IllegalArgumentException expected) {
        }
    }
}