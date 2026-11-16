package org.tron.common.utils;

import org.bouncycastle.util.encoders.DecoderException;
import org.junit.Assert;
import org.junit.Test;

public class ByteArrayHexTest {

    @Test
    public void hexPrefixes_decodeToSameBytes() {
        byte[] expected = {(byte) 0x00, (byte) 0xab, (byte) 0xcd};
        for (String input : new String[] {"00abcd", "0x00aBcD", "0X00ABCD"}) {
            Assert.assertArrayEquals(expected, ByteArray.fromHexString(input));
        }
    }

    @Test
    public void emptyAndOddLengthHex_preserveExistingBehavior() {
        Assert.assertArrayEquals(new byte[0], ByteArray.fromHexString(null));
        for (String prefix : new String[] {"", "0x", "0X"}) {
            Assert.assertArrayEquals(new byte[0], ByteArray.fromHexString(prefix));
            Assert.assertArrayEquals(new byte[] {0x0a, (byte) 0xbc},
                    ByteArray.fromHexString(prefix + "abc"));
        }
    }

    @Test
    public void malformedHex_isStillRejected() {
        for (String input : new String[] {"0Xgg", "0X0X01", "0x0X01", "0y01"}) {
            try {
                ByteArray.fromHexString(input);
                Assert.fail("Expected rejection for invalid hex: " + input);
            } catch (DecoderException expected) {
                // Prefix support must not weaken validation of the remaining hex digits.
            }
        }
    }
}
