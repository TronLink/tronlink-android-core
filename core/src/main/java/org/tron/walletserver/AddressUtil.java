package org.tron.walletserver;

import org.tron.common.crypto.Hash;
import org.tron.common.utils.Base58;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.LogUtils;
import org.tron.common.utils.Sha256Hash;
import org.tron.config.Parameter;

/**
 * String handling tools
 */
public class AddressUtil {
    public static final String EMPTY_STRING = "";

    private static final String TAG = "AddressUtil";
    private static final int HEX_ADDRESS_LENGTH = 42;

    /**
     * Determine if it is empty
     *
     * @param text
     * @return
     */
    public static boolean isNullOrEmpty(String text) {
        if (text == null || "".equals(text.trim()) || text.trim().length() == 0
                || "null".equals(text.trim())) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Determine if a string in the string array texts is empty
     *
     * @param texts
     * @return If one of the string array texts is empty or texts is empty， return ;otherwise return false;
     */
    public static boolean isEmpty(String... texts) {
        if (texts == null || texts.length == 0) {
            return true;
        }
        for (String text : texts) {
            if (text == null || "".equals(text.trim()) || text.trim().length() == 0
                    || "null".equals(text.trim())) {
                return true;
            }
        }
        return false;
    }

    /**
     * substring the string, remove the content after the sign String
     *
     * @param source raw string
     * @param sign   the sign String
     * @return
     */
    public static String splitByIndex(String source, String sign) {
        String temp = "";
        if (isNullOrEmpty(source)) {
            return temp;
        }
        int length = source.indexOf(sign);
        if (length > -1) {
            temp = source.substring(0, length);
        } else {
            return source;
        }
        return temp;
    }


    public static boolean isAddressValid(byte[] address) {
        if (address == null || address.length == 0) {
            return false;
        }
        if (address.length != Parameter.CommonConstant.ADDRESS_SIZE) {
            return false;
        }
        byte preFixbyte = address[0];
        if (preFixbyte != Parameter.CommonConstant.ADD_PRE_FIX_BYTE) {
            return false;
        }

        return true;
    }

    public static boolean isAddressValid(String address) {
        if (isEmpty(address)) return false;
        return isAddressValid(decodeFromBase58Check(address));
    }

    public static String encode58Check(byte[] input) {
        byte[] hash0 = Sha256Hash.hash(input);
        byte[] hash1 = Sha256Hash.hash(hash0);
        byte[] inputCheck = new byte[input.length + 4];
        System.arraycopy(input, 0, inputCheck, 0, input.length);
//        LogUtils.d(TAG, "input："+Hex.toHexString(input) +"---hash0："+Hex.toHexString(hash0)+"---hash1："+Hex.toHexString(hash1));
        System.arraycopy(hash1, 0, inputCheck, input.length, 4);
//        LogUtils.d(TAG, "input："+Hex.toHexString(input) + "---inputCheck:"+Hex.toHexString(inputCheck));
        return Base58.encode(inputCheck);
    }


    public static String replace41Address(String address) {
        if (address == null) {
            // Fail fast on malformed input instead of throwing a bare NPE on
            // startsWith below. Address callers (ABI/EIP-712 encoding) handle
            // external input, so surface the error rather than silently continue.
            throw new IllegalArgumentException("address must not be null");
        }
        String unPreAddress = address;
        if (address.startsWith("T")) {
            byte[] decoded = AddressUtil.decode58Check(address);
            if (decoded == null) {
                // decode58Check returns null on a bad checksum/length. Fail fast
                // instead of toHexString(null) producing an empty/garbage address
                // that would flow into signing or transaction construction.
                throw new IllegalArgumentException("invalid base58 address");
            }
            unPreAddress = ByteArray.toHexString(decoded);

            return unPreAddress.replaceFirst("41", "");
        } else if (address.startsWith("41")) {
            return unPreAddress.replaceFirst("41", "");
        } else if (address.startsWith("0x")) {
            return unPreAddress.replaceFirst("0x", "");
        }
        // No recognized prefix: assume the input is already raw hex and return as-is.
        return unPreAddress;
    }

    public static byte[] decode58Check(String input) {
        try {
            byte[] decodeCheck = Base58.decode(input);
            if (decodeCheck.length <= 4) {
                return null;
            }
            byte[] decodeData = new byte[decodeCheck.length - 4];
            System.arraycopy(decodeCheck, 0, decodeData, 0, decodeData.length);
            byte[] hash0 = Hash.sha256(decodeData);
            byte[] hash1 = Hash.sha256(hash0);
            if (hash1[0] == decodeCheck[decodeData.length] &&
                    hash1[1] == decodeCheck[decodeData.length + 1] &&
                    hash1[2] == decodeCheck[decodeData.length + 2] &&
                    hash1[3] == decodeCheck[decodeData.length + 3]) {
                return decodeData;
            }
            return null;
        } catch (IllegalArgumentException e) {
            // Only IllegalArgumentException is treated as "invalid Base58 input" and
            // mapped to null. Other RuntimeExceptions are intentionally left to
            // propagate so callers do not silently consume an unexpected failure.
            LogUtils.e(TAG, "decode58Check failed for invalid Base58 input: " + e.getMessage());
            return null;
        }
    }

    public static byte[] decodeFromBase58Check(String addressBase58) {
        if (isEmpty(addressBase58)) {
            return null;
        }
        byte[] address = decode58Check(addressBase58);
        if (!isAddressValid(address)) {
            return null;
        }
        return address;
    }

    /**
     * Decodes either a Base58Check address beginning with {@code T} or a hex address beginning
     * with {@code 41}. Returns {@code null} when the input is not a supported valid address.
     */
    public static byte[] decodeUnknownAddress(String address) {
        if (isEmpty(address)) {
            return null;
        }

        String normalizedAddress = address.trim();
        if (normalizedAddress.startsWith("T")) {
            return decodeFromBase58Check(normalizedAddress);
        }
        if (normalizedAddress.length() == HEX_ADDRESS_LENGTH
                && normalizedAddress.startsWith("41")
                && isHexString(normalizedAddress)) {
            byte[] decoded = ByteArray.fromHexString(normalizedAddress);
            return isAddressValid(decoded) ? decoded : null;
        }
        return null;
    }


    public static String zeros(int n) {
        return repeat('0', n);
    }

    public static String repeat(char value, int n) {
        return new String(new char[n]).replace("\0", String.valueOf(value));
    }

    /**
     * Check if a string is in hexadecimal
     *
     * @param hexString
     * @return
     */
    public static boolean isHexString(String hexString) {
        if (isEmpty(hexString)) return false;
        String regex = "^[A-Fa-f0-9]+$";
        if (hexString.matches(regex)) {
            return true;
        } else {
            return false;
        }
    }


}
