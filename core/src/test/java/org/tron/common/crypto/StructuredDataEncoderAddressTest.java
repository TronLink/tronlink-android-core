package org.tron.common.crypto;

import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.tron.common.utils.ByteArray;
import org.tron.walletserver.AddressUtil;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * The confirmation page renders values from getParseAddressList() as Base58, while the hash
 * uses replace41Address. Both must classify an address the same way, otherwise the page shows
 * a different address from the one being signed.
 */
public class StructuredDataEncoderAddressTest {

    private static final String BODY_20 = "415cb7e83668d78451a236c86de505d5ff502441";
    private static final String TRON_HEX = "41" + BODY_20;
    private static final String NUMERIC_ADDRESS = "0000000000000000000000000000000000000010";

    private static String singleAddressJson(String address) {
        return "{"
                + "\"types\":{"
                + "\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"}],"
                + "\"Payload\":[{\"name\":\"to\",\"type\":\"address\"}]"
                + "},"
                + "\"primaryType\":\"Payload\","
                + "\"domain\":{\"name\":\"Test\"},"
                + "\"message\":{\"to\":\"" + address + "\"}"
                + "}";
    }

    private static String addressArrayJson(String... addresses) {
        return addressArrayJsonWithType("address[]", addresses);
    }

    private static String addressArrayJsonWithType(String type, String... addresses) {
        StringBuilder array = new StringBuilder();
        for (int i = 0; i < addresses.length; i++) {
            if (i > 0) {
                array.append(',');
            }
            array.append('"').append(addresses[i]).append('"');
        }
        return "{"
                + "\"types\":{"
                + "\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"}],"
                + "\"Payload\":[{\"name\":\"to\",\"type\":\"" + type + "\"}]"
                + "},"
                + "\"primaryType\":\"Payload\","
                + "\"domain\":{\"name\":\"Test\"},"
                + "\"message\":{\"to\":[" + array + "]}"
                + "}";
    }

    private static byte[] hashSingle(String address) throws Exception {
        return new StructuredDataEncoder(singleAddressJson(address)).hashMessage();
    }

    private static List<String> parsedSingle(String address) throws Exception {
        StructuredDataEncoder encoder = new StructuredDataEncoder(singleAddressJson(address));
        encoder.hashMessage();
        return encoder.getParseAddressList();
    }

    @Test
    public void addressField_allTronFormsHashTheSame() throws Exception {
        String base58 = AddressUtil.encode58Check(Hex.decode(TRON_HEX));
        byte[] expected = hashSingle("0x" + BODY_20);

        Assert.assertArrayEquals(expected, hashSingle(TRON_HEX));
        Assert.assertArrayEquals(expected, hashSingle("0x" + TRON_HEX));
        Assert.assertArrayEquals(expected, hashSingle("0X" + TRON_HEX));
        Assert.assertArrayEquals(expected, hashSingle("0X" + BODY_20));
        Assert.assertArrayEquals(expected, hashSingle(base58));
        Assert.assertArrayEquals(expected, hashSingle(BODY_20));
    }

    @Test
    public void addressField_tronHexFormsAreListedForBase58Display() throws Exception {
        Assert.assertTrue(parsedSingle(TRON_HEX).contains(TRON_HEX));
        Assert.assertTrue(parsedSingle("0x" + TRON_HEX).contains("0x" + TRON_HEX));
        Assert.assertTrue(parsedSingle("0X" + TRON_HEX).contains("0X" + TRON_HEX));
    }

    @Test
    public void addressField_tronHexForms_convertToExpectedBase58Display() throws Exception {
        for (String address : new String[] {TRON_HEX, "0x" + TRON_HEX, "0X" + TRON_HEX}) {
            List<String> parsed = parsedSingle(address);
            Assert.assertEquals(1, parsed.size());
            assertBase58Display(parsed.get(0));
        }
    }

    @Test
    public void addressArray_tronHexForms_convertToExpectedBase58Display() throws Exception {
        StructuredDataEncoder encoder = new StructuredDataEncoder(
                addressArrayJson(TRON_HEX, "0x" + TRON_HEX, "0X" + TRON_HEX));
        encoder.hashStructuredData();
        List<String> parsed = encoder.getParseAddressList();
        Assert.assertEquals(3, parsed.size());
        for (String address : parsed) {
            assertBase58Display(address);
        }
    }

    private static void assertBase58Display(String address) {
        // Exercise the hex-to-Base58 conversion used by the confirmation page,
        // including the network byte that must remain in the displayed address.
        byte[] decoded = ByteArray.fromHexString(address);
        Assert.assertArrayEquals(Hex.decode(TRON_HEX), decoded);
        Assert.assertEquals("TFvoziPeoRT22yALpyv6rioFi5Z2NchE5N", AddressUtil.encode58Check(decoded));
    }

    @Test
    public void addressField_raw20ByteAddressStartingWith41_isNotListed() throws Exception {
        Assert.assertTrue(parsedSingle(BODY_20).isEmpty());
        Assert.assertTrue(parsedSingle("0x" + BODY_20).isEmpty());
        Assert.assertTrue(parsedSingle("0X" + BODY_20).isEmpty());
    }

    @Test
    public void addressArray_listsOnlyTronHexForms() throws Exception {
        StructuredDataEncoder encoder = new StructuredDataEncoder(
                addressArrayJson(TRON_HEX, "0x" + TRON_HEX, "0X" + TRON_HEX,
                        BODY_20, "0x" + BODY_20, "0X" + BODY_20));
        encoder.hashMessage();
        List<String> parsed = encoder.getParseAddressList();

        Assert.assertTrue(parsed.contains(TRON_HEX));
        Assert.assertTrue(parsed.contains("0x" + TRON_HEX));
        Assert.assertTrue(parsed.contains("0X" + TRON_HEX));
        Assert.assertFalse(parsed.contains(BODY_20));
        Assert.assertFalse(parsed.contains("0x" + BODY_20));
        Assert.assertFalse(parsed.contains("0X" + BODY_20));
    }

    @Test
    public void addressArray_allFormsOfSameAddressHashTheSame() throws Exception {
        byte[] expected = new StructuredDataEncoder(addressArrayJson("0x" + BODY_20)).hashMessage();

        Assert.assertArrayEquals(expected,
                new StructuredDataEncoder(addressArrayJson(TRON_HEX)).hashMessage());
        Assert.assertArrayEquals(expected,
                new StructuredDataEncoder(addressArrayJson("0x" + TRON_HEX)).hashMessage());
        Assert.assertArrayEquals(expected,
                new StructuredDataEncoder(addressArrayJson(BODY_20)).hashMessage());
        Assert.assertArrayEquals(expected,
                new StructuredDataEncoder(addressArrayJson("0X" + BODY_20)).hashMessage());
        Assert.assertArrayEquals(expected,
                new StructuredDataEncoder(addressArrayJson("0X" + TRON_HEX)).hashMessage());
    }

    @Test
    public void addressArray_numericAddressAllForms_matchReferenceDigest() throws Exception {
        String tronHex = "41" + NUMERIC_ADDRESS;
        String base58 = AddressUtil.encode58Check(Hex.decode(tronHex));
        byte[] expected = referenceArrayDigest("address[]", NUMERIC_ADDRESS);
        for (String address : new String[] {
                NUMERIC_ADDRESS, "0x" + NUMERIC_ADDRESS, "0X" + NUMERIC_ADDRESS,
                tronHex, "0x" + tronHex, "0X" + tronHex, base58}) {
            Assert.assertArrayEquals(address, expected,
                    new StructuredDataEncoder(addressArrayJson(address)).hashStructuredData());
        }
    }

    @Test
    public void addressArray_numericAddress_doesNotCollideWithDecimalEquivalent() throws Exception {
        String decimalEquivalent = "000000000000000000000000000000000000000a";
        byte[] hex16 = new StructuredDataEncoder(
                addressArrayJson("0x" + NUMERIC_ADDRESS)).hashStructuredData();
        byte[] hex10 = new StructuredDataEncoder(
                addressArrayJson("0x" + decimalEquivalent)).hashStructuredData();

        Assert.assertFalse(Arrays.equals(hex16, hex10));
        Assert.assertArrayEquals(referenceArrayDigest("address[]", decimalEquivalent), hex10);
    }

    @Test
    public void fixedAddressArray_numericAnd41Payload_matchReferenceDigest() throws Exception {
        Assert.assertArrayEquals(referenceArrayDigest("address[2]", NUMERIC_ADDRESS, BODY_20),
                new StructuredDataEncoder(addressArrayJsonWithType(
                        "address[2]", "41" + NUMERIC_ADDRESS, TRON_HEX)).hashStructuredData());
    }

    @Test
    public void addressArray_variableWidthHex_matchesScalarAndReference() throws Exception {
        byte[] expectedArray = referenceArrayDigest("address[]", NUMERIC_ADDRESS);
        byte[] expectedScalar = hashSingle(NUMERIC_ADDRESS);
        for (String address : new String[] {
                "10", "0x10", "0X10", "00010",
                NUMERIC_ADDRESS.substring(1), "00" + NUMERIC_ADDRESS}) {
            // Preserve scalar-address compatibility: shorter hex and extra leading zeros
            // represent the same address, and are encoded as hexadecimal rather than decimal.
            Assert.assertArrayEquals(address, expectedScalar, hashSingle(address));
            Assert.assertArrayEquals(address, expectedArray,
                    new StructuredDataEncoder(addressArrayJson(address)).hashStructuredData());
        }
    }

    // Independent EIP-712 oracle: do not reuse production address or ABI encoding helpers.
    private static byte[] referenceArrayDigest(String type, String... hexAddresses) {
        byte[] words = new byte[32 * hexAddresses.length];
        for (int i = 0; i < hexAddresses.length; i++) {
            byte[] address = Hex.decode(hexAddresses[i]);
            Assert.assertEquals(20, address.length);
            System.arraycopy(address, 0, words, 32 * i + 12, address.length);
        }
        byte[] domainHash = keccak(
                keccak("EIP712Domain(string name)".getBytes(StandardCharsets.UTF_8)),
                keccak("Test".getBytes(StandardCharsets.UTF_8)));
        byte[] messageHash = keccak(
                keccak(("Payload(" + type + " to)").getBytes(StandardCharsets.UTF_8)),
                keccak(words));
        return keccak(new byte[] {0x19, 0x01}, domainHash, messageHash);
    }

    private static byte[] keccak(byte[]... parts) {
        Keccak.Digest256 digest = new Keccak.Digest256();
        for (byte[] part : parts) {
            digest.update(part, 0, part.length);
        }
        return digest.digest();
    }
}
