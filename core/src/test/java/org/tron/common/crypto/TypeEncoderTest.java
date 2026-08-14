package org.tron.common.crypto;

import org.junit.Assert;
import org.junit.Test;
import org.tron.common.crypto.datatypes.DynamicArray;
import org.tron.common.crypto.datatypes.Utf8String;

import java.util.List;

/**
 * Regression tests for Q-07: string[] element offsets were computed from
 * String.length() (UTF-16 code units) while tails are encoded as UTF-8, so
 * multi-byte elements shifted every subsequent offset by whole words.
 */
public class TypeEncoderTest {

    /** Left-pads a hex value to a full 32-byte (64 hex char) ABI word. */
    private static String word(String hexValue) {
        StringBuilder sb = new StringBuilder(64);
        for (int i = hexValue.length(); i < 64; i++) {
            sb.append('0');
        }
        return sb.append(hexValue).toString();
    }

    private static String repeat(String s, int times) {
        StringBuilder sb = new StringBuilder(s.length() * times);
        for (int i = 0; i < times; i++) {
            sb.append(s);
        }
        return sb.toString();
    }

    private static List<Utf8String> roundTrip(DynamicArray<Utf8String> array) {
        DynamicArray<Utf8String> decoded =
                TypeDecoder.decodeDynamicArray(
                        TypeEncoder.encode(array),
                        0,
                        new TypeReference<DynamicArray<Utf8String>>() {});
        return decoded.getValue();
    }

    @Test
    public void encodeStringArray_cjkElement_offsetCountsUtf8Bytes() {
        // 20 CJK chars: String.length() == 20 (1 word) but UTF-8 == 60 bytes (2 words).
        String cjk = repeat("好", 20);
        DynamicArray<Utf8String> array =
                new DynamicArray<>(Utf8String.class, new Utf8String(cjk), new Utf8String("b"));

        String encoded = TypeEncoder.encode(array);
        // Layout: count, offset(s1), offset(s2), then tails.
        Assert.assertEquals(word("2"), encoded.substring(0, 64));
        Assert.assertEquals(word("40"), encoded.substring(64, 128));
        // s2 starts after s1's tail: 64 (offsets end) + 32 (length word) + 64 (60
        // bytes padded to 2 words) = 160. Pre-fix this was 128 — one word short.
        Assert.assertEquals(word("a0"), encoded.substring(128, 192));
        // s1's declared length is its UTF-8 byte count.
        Assert.assertEquals(word("3c"), encoded.substring(192, 256));
    }

    @Test
    public void encodeStringArray_cjkElement_roundTrips() {
        String cjk = repeat("好", 20);
        DynamicArray<Utf8String> array =
                new DynamicArray<>(Utf8String.class, new Utf8String(cjk), new Utf8String("b"));

        List<Utf8String> decoded = roundTrip(array);
        Assert.assertEquals(2, decoded.size());
        Assert.assertEquals(cjk, decoded.get(0).getValue());
        Assert.assertEquals("b", decoded.get(1).getValue());
    }

    @Test
    public void encodeStringArray_surrogatePairs_roundTrips() {
        // 9 emoji: String.length() == 18 (1 word) but UTF-8 == 36 bytes (2 words).
        String emoji = repeat("😀", 9);
        DynamicArray<Utf8String> array =
                new DynamicArray<>(Utf8String.class, new Utf8String(emoji), new Utf8String("tail"));

        List<Utf8String> decoded = roundTrip(array);
        Assert.assertEquals(2, decoded.size());
        Assert.assertEquals(emoji, decoded.get(0).getValue());
        Assert.assertEquals("tail", decoded.get(1).getValue());
    }

    @Test
    public void encodeStringArray_ascii_unchanged() {
        DynamicArray<Utf8String> array =
                new DynamicArray<>(Utf8String.class, new Utf8String("abc"), new Utf8String("d"));

        String encoded = TypeEncoder.encode(array);
        // ASCII: UTF-16 and UTF-8 lengths agree, offsets are as before the fix.
        Assert.assertEquals(word("80"), encoded.substring(128, 192));

        List<Utf8String> decoded = roundTrip(array);
        Assert.assertEquals("abc", decoded.get(0).getValue());
        Assert.assertEquals("d", decoded.get(1).getValue());
    }
}
