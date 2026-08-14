package org.tron.common.crypto;

import org.junit.Assert;
import org.junit.Test;
import org.tron.common.crypto.datatypes.DynamicArray;
import org.tron.common.crypto.datatypes.DynamicBytes;
import org.tron.common.crypto.datatypes.generated.StaticArray2;
import org.tron.common.crypto.datatypes.generated.Uint256;

import java.math.BigInteger;

public class TypeDecoderTest {

    /** A full 32-byte (64 hex char) ABI word encoding the value 1. */
    private static final String WORD_ONE =
            "0000000000000000000000000000000000000000000000000000000000000001";

    /** Left-pads a hex value to a full 32-byte (64 hex char) ABI word. */
    private static String word(String hexValue) {
        StringBuilder sb = new StringBuilder(64);
        for (int i = hexValue.length(); i < 64; i++) {
            sb.append('0');
        }
        return sb.append(hexValue).toString();
    }

    @Test(expected = TypeMappingException.class)
    public void decodeNumeric_truncatedInput_throwsTypeMappingException() {
        // "1234" is 2 bytes — far short of the 32-byte ABI word width.
        TypeDecoder.decodeNumeric("1234", Uint256.class);
    }

    @Test
    public void decodeNumeric_fullWord_decodesValue() {
        Uint256 value = TypeDecoder.decodeNumeric(WORD_ONE, Uint256.class);
        Assert.assertEquals(BigInteger.ONE, value.getValue());
    }

    // S-07 regression: length/offset words from attacker-controlled return data
    // must not be truncated by intValue() or drive oversized allocations.

    @Test
    public void decodeUintAsInt_smallValue_decodes() {
        Assert.assertEquals(1, TypeDecoder.decodeUintAsInt(WORD_ONE, 0));
    }

    @Test(expected = TypeMappingException.class)
    public void decodeUintAsInt_uint256Max_throwsInsteadOfTruncating() {
        // Pre-fix, intValue() truncated this to -1.
        String allFs = word("").replace('0', 'f');
        TypeDecoder.decodeUintAsInt(allFs, 0);
    }

    @Test(expected = TypeMappingException.class)
    public void decodeUintAsInt_aboveIntMax_throws() {
        // 2^31 — one past Integer.MAX_VALUE; intValue() would wrap negative.
        TypeDecoder.decodeUintAsInt(word("80000000"), 0);
    }

    @Test
    public void decodeDynamicBytes_validLength_decodes() {
        String data = "abcdef" + word("").substring(6); // 3 bytes, right-padded
        DynamicBytes bytes = TypeDecoder.decodeDynamicBytes(word("3") + data, 0);
        Assert.assertArrayEquals(
                new byte[] {(byte) 0xab, (byte) 0xcd, (byte) 0xef}, bytes.getValue());
    }

    @Test(expected = TypeMappingException.class)
    public void decodeDynamicBytes_declaredLengthBeyondInput_throws() {
        // Declares 64 bytes but only one 32-byte word of data follows.
        TypeDecoder.decodeDynamicBytes(word("40") + word(""), 0);
    }

    @Test
    public void decodeDynamicArray_validLength_decodes() {
        String input = word("2") + WORD_ONE + word("2");
        DynamicArray<Uint256> result =
                TypeDecoder.decodeDynamicArray(
                        input, 0, new TypeReference<DynamicArray<Uint256>>() {});
        Assert.assertEquals(2, result.getValue().size());
        Assert.assertEquals(BigInteger.ONE, result.getValue().get(0).getValue());
        Assert.assertEquals(BigInteger.valueOf(2), result.getValue().get(1).getValue());
    }

    @Test(expected = TypeMappingException.class)
    public void decodeDynamicArray_declaredCountBeyondInput_throws() {
        // Declares Integer.MAX_VALUE elements backed by a single word of data.
        // Pre-fix, decodeArrayElements pre-sized new ArrayList<>(Integer.MAX_VALUE).
        String input = word("7fffffff") + WORD_ONE;
        TypeDecoder.decodeDynamicArray(input, 0, new TypeReference<DynamicArray<Uint256>>() {});
    }

    @Test
    public void decodeTypeReference_dynamicArray_usesRawArrayType() {
        TypeReference<DynamicArray<Uint256>> reference =
                new TypeReference<DynamicArray<Uint256>>() { };
        String input = word("2") + word("1") + word("2");

        DynamicArray<Uint256> decoded = TypeDecoder.decode(input, 0, reference);

        Assert.assertEquals(2, decoded.getValue().size());
        Assert.assertEquals(BigInteger.ONE, decoded.getValue().get(0).getValue());
        Assert.assertEquals(BigInteger.valueOf(2), decoded.getValue().get(1).getValue());
    }

    @Test
    public void decodeTypeReference_staticArray_usesDeclaredSize() {
        TypeReference<StaticArray2<Uint256>> reference =
                new TypeReference<StaticArray2<Uint256>>() { };
        String input = word("1") + word("2");

        StaticArray2<Uint256> decoded = TypeDecoder.decode(input, 0, reference);

        Assert.assertEquals(2, decoded.getValue().size());
        Assert.assertEquals(BigInteger.ONE, decoded.getValue().get(0).getValue());
        Assert.assertEquals(BigInteger.valueOf(2), decoded.getValue().get(1).getValue());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void decodeGeneratedStaticArrayReference_usesReferenceSize() throws Exception {
        TypeReference<StaticArray2<Uint256>> reference =
                (TypeReference<StaticArray2<Uint256>>) TypeReference.makeTypeReference("uint256[2]");

        StaticArray2<Uint256> decoded =
                TypeDecoder.decode(word("1") + word("2"), 0, reference);

        Assert.assertEquals(2, decoded.getValue().size());
        Assert.assertEquals(BigInteger.valueOf(2), decoded.getValue().get(1).getValue());
    }
}
