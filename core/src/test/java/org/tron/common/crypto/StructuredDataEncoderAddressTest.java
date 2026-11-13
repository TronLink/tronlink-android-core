package org.tron.common.crypto;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.tron.walletserver.AddressUtil;

import java.util.List;

/**
 * The confirmation page renders values from getParseAddressList() as Base58, while the hash
 * uses replace41Address. Both must classify an address the same way, otherwise the page shows
 * a different address from the one being signed.
 */
public class StructuredDataEncoderAddressTest {

    private static final String BODY_20 = "415cb7e83668d78451a236c86de505d5ff502441";
    private static final String TRON_HEX = "41" + BODY_20;

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
                + "\"Payload\":[{\"name\":\"to\",\"type\":\"address[]\"}]"
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
        Assert.assertArrayEquals(expected, hashSingle(base58));
        Assert.assertArrayEquals(expected, hashSingle(BODY_20));
    }

    @Test
    public void addressField_tronHexFormsAreListedForBase58Display() throws Exception {
        Assert.assertTrue(parsedSingle(TRON_HEX).contains(TRON_HEX));
        Assert.assertTrue(parsedSingle("0x" + TRON_HEX).contains("0x" + TRON_HEX));
    }

    @Test
    public void addressField_raw20ByteAddressStartingWith41_isNotListed() throws Exception {
        Assert.assertTrue(parsedSingle(BODY_20).isEmpty());
        Assert.assertTrue(parsedSingle("0x" + BODY_20).isEmpty());
    }

    @Test
    public void addressArray_listsOnlyTronHexForms() throws Exception {
        StructuredDataEncoder encoder = new StructuredDataEncoder(
                addressArrayJson(TRON_HEX, "0x" + TRON_HEX, BODY_20, "0x" + BODY_20));
        encoder.hashMessage();
        List<String> parsed = encoder.getParseAddressList();

        Assert.assertTrue(parsed.contains(TRON_HEX));
        Assert.assertTrue(parsed.contains("0x" + TRON_HEX));
        Assert.assertFalse(parsed.contains(BODY_20));
        Assert.assertFalse(parsed.contains("0x" + BODY_20));
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
    }
}
