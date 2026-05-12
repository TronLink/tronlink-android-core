package org.tron.common.utils.abi;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.ToNumberPolicy;
import com.google.gson.reflect.TypeToken;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Hex;
import org.tron.common.crypto.Hash;
import org.tron.common.utils.DecimalUtils;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.ByteUtil;
import org.tron.common.utils.GsonFormatUtils;
import org.tron.common.utils.LogUtils;
import org.tron.walletserver.AddressUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AbiUtil {

    private static Pattern paramTypeBytes = Pattern.compile("^bytes([0-9]*)$");
    private static Pattern paramTypeNumber = Pattern.compile("^(u?int)([0-9]*)$");
    private static Pattern paramTypeArray = Pattern.compile("^(.*)\\[([0-9]*)]$");

    // LAZILY_PARSED_NUMBER keeps the raw JSON numeric literal so uint256 values
    // survive toString() without Long/Double precision loss.
    private static final Gson LIST_GSON = new GsonBuilder()
        .setObjectToNumberStrategy(ToNumberPolicy.LAZILY_PARSED_NUMBER)
        .create();

    static abstract class Coder {
        boolean dynamic = false;

        //    DataWord[] encode
        abstract byte[] encode(String value);

        abstract byte[] decode();

    }

    public static String[] getTypes(String methodSign) {
        int start = methodSign.indexOf('(') + 1;
        int end = methodSign.lastIndexOf(')');
        try {
            String typeString = methodSign.subSequence(start, end).toString();
            if (typeString.contains("tuple")) {
                int startTuple = typeString.indexOf("tuple");
                int endTuple = typeString.lastIndexOf(")") + 1;
                String tupleString = typeString.substring(startTuple, endTuple);
                String[] splitNoTuple = typeString.substring(0, startTuple).split(",");
                String[] all = Arrays.copyOf(splitNoTuple, splitNoTuple.length + 1);
                all[splitNoTuple.length] = tupleString;
                return all;
            } else {
                return typeString.split(",");
            }
        } catch (Exception e) {
            LogUtils.e(e);
        }
        return new String[0];
    }


    private static Coder getParamCoder(String type) {
        String switchType = type;
        if (type.contains("tuple")) {
            switchType = "tuple";
        } else {
            switchType = type;
        }
        switch (switchType) {
            case "address":
                return new CoderAddress();
            case "string":
                return new CoderString();
            case "bool":
                return new CoderBool();
            case "bytes":
                return new CoderDynamicBytes();
            case "trcToken":
                return new CoderNumber();
            case "tuple":
                return new CoderTuple(type);
        }

        if (paramTypeBytes.matcher(switchType).find()) {
            return new CoderFixedBytes();
        }

        if (paramTypeNumber.matcher(switchType).find()) {
            return new CoderNumber();
        }

        Matcher m = paramTypeArray.matcher(switchType);
        if (m.find()) {
            String arrayType = m.group(1);
            int length = -1;
            if (!m.group(2).equals("")) {
                length = Integer.valueOf(m.group(2));
            }
            return new CoderArray(arrayType, length);
        }
        return null;
    }

    static class CoderArray extends Coder {
        private String elementType;
        private int length;

        CoderArray(String arrayType, int length) {
            this.elementType = arrayType;
            this.length = length;
            this.dynamic = (length == -1);
        }

        @Override
        byte[] encode(String arrayValues) {

            Coder coder = getParamCoder(elementType);
            if (coder == null) {
                throw new IllegalArgumentException("Unknown ABI type: " + elementType);
            }

            List strings;
            try {
                strings = LIST_GSON.fromJson(arrayValues,
                    new TypeToken<List<Object>>(){}.getType());
            } catch (Exception e) {
                LogUtils.e(e);
                return null;
            }

            List<Coder> coders = new ArrayList<>();

            if (this.length == -1) {
                for (int i = 0; i < strings.size(); i++) {
                    coders.add(coder);
                }
            } else {
                for (int i = 0; i < this.length; i++) {
                    coders.add(coder);
                }
            }

            if (this.length == -1) {
                return ByteUtil.merge(new DataWord(strings.size()).getData(), pack(coders, strings));
            } else {
                return pack(coders, strings);
            }
        }

        @Override
        byte[] decode() {
            return new byte[0];
        }
    }

    static class CoderTuple extends Coder {
        private String elementTypes;
        private List<String> elementTypeList = new ArrayList<>();
        private int length;

        CoderTuple(String elementTypes) {
            this.elementTypes = elementTypes;
            if (AddressUtil.isEmpty(elementTypes)) return;
            int start = elementTypes.indexOf('(') + 1;
            int end = elementTypes.lastIndexOf(')');
            String types = elementTypes.subSequence(start, end).toString();
            if (types != null) {
                String[] split = types.split(",");
                if (split != null && split.length != 0) {
                    elementTypeList = Arrays.asList(split);
                    length = elementTypeList.size();
                }
            }
            this.dynamic = false;
        }

        @Override
        byte[] encode(String arrayValues) {
            List<Coder> coders = new ArrayList<>();
            for (int i = 0; i < elementTypeList.size(); i++) {
                coders.add(getParamCoder(elementTypeList.get(i)));
            }

            List strings;
            try {
                strings = LIST_GSON.fromJson(arrayValues,
                    new TypeToken<List<Object>>(){}.getType());
            } catch (Exception e) {
                LogUtils.e(e);
                return null;
            }

            if (this.length == -1) {
                return ByteUtil.merge(new DataWord(strings.size()).getData(), pack(coders, strings));
            } else {
                return pack(coders, strings);
            }
        }

        @Override
        byte[] decode() {
            return new byte[0];
        }
    }

    static class CoderNumber extends Coder {

        @Override
        byte[] encode(String value) {
            value = DecimalUtils.toString(DecimalUtils.toBigDecimal(value));
            if (!AddressUtil.isEmpty(value) && value.contains("."))
                value = AddressUtil.splitByIndex(value, ".");
            BigInteger bigInteger = new BigInteger(value);

            byte[] bytes = bigInteger.abs().toByteArray();

            /**
             * TODO The original data is 32-bit BigInteger after processing, and the sign bit is removed.（0x00）
             * 4.0.2 Added NFT version to handle uint 256 maximum value error
             */
            if (bytes.length == 33 && bytes[0] == 0) {
                byte[] tmp = new byte[bytes.length - 1];
                System.arraycopy(bytes, 1, tmp, 0, tmp.length);
                bytes = tmp;
            }

            DataWord word = new DataWord(bytes);
            if (bigInteger.compareTo(new BigInteger("0")) == -1) {
                word.negate();
            }
            return word.getData();
        }

        @Override
        byte[] decode() {
            return new byte[0];
        }
    }

    static class CoderFixedBytes extends Coder {

        @Override
        byte[] encode(String value) {

            if (value.startsWith("0x")) {
                value = value.substring(2);
            }

            if (value.length() % 2 != 0) {
                value = "0" + value;
            }

            byte[] result = new byte[32];
            byte[] bytes = Hex.decode(value);
            System.arraycopy(bytes, 0, result, 0, bytes.length);
            return result;
        }

        @Override
        byte[] decode() {
            return new byte[0];
        }
    }

    static class CoderDynamicBytes extends Coder {

        CoderDynamicBytes() {
            dynamic = true;
        }

        @Override
        byte[] encode(String value) {
            return encodeDynamicBytes(value, true);
        }

        @Override
        byte[] decode() {
            return new byte[0];
        }
    }

    static class CoderBool extends Coder {

        @Override
        byte[] encode(String value) {
            if (value.equals("true") || value.equals("1")) {
                return new DataWord(1).getData();
            } else {
                return new DataWord(0).getData();
            }

        }

        @Override
        byte[] decode() {
            return new byte[0];
        }
    }

    static class CoderAddress extends Coder {

        @Override
        byte[] encode(String value) {
            value = AddressUtil.replace41Address(value);
            byte[] address = ByteArray.fromHexString(value);
            if (address == null) {
                return null;
            }
            return new DataWord(address).getData();
        }

        @Override
        byte[] decode() {
            return new byte[0];
        }
    }

    static class CoderString extends Coder {
        CoderString() {
            dynamic = true;
        }

        @Override
        byte[] encode(String value) {
            return encodeDynamicBytes(value);
        }

        @Override
        byte[] decode() {
            return new byte[0];
        }
    }

    private static byte[] encodeDynamicBytes(String value, boolean hex) {
        byte[] data;
        if (hex) {
            if (value.startsWith("0x")) {
                value = value.substring(2);
            }
            data = Hex.decode(value);
        } else {
            data = value.getBytes();
        }
        return encodeDynamicBytes(data);
    }

    private static byte[] encodeDynamicBytes(byte[] data) {
        List<DataWord> ret = new ArrayList<>();
        ret.add(new DataWord(data.length));

        int readInx = 0;
        int len = data.length;
        while (readInx < data.length) {
            byte[] wordData = new byte[32];
            int readLen = len - readInx >= 32 ? 32 : (len - readInx);
            System.arraycopy(data, readInx, wordData, 0, readLen);
            DataWord word = new DataWord(wordData);
            ret.add(word);
            readInx += 32;
        }

        byte[] retBytes = new byte[ret.size() * 32];
        int retIndex = 0;

        for (DataWord w : ret) {
            System.arraycopy(w.getData(), 0, retBytes, retIndex, 32);
            retIndex += 32;
        }

        return retBytes;
    }

    private static byte[] encodeDynamicBytes(String value) {
        byte[] data = value.getBytes();
        List<DataWord> ret = new ArrayList<>();
        ret.add(new DataWord(data.length));
        return encodeDynamicBytes(data);
    }

    public static byte[] pack(List<Coder> codes, List<Object> values) {

        int staticSize = 0;
        int dynamicSize = 0;

        List<byte[]> encodedList = new ArrayList<>();

        for (int idx = 0; idx < codes.size(); idx++) {
            Coder coder = codes.get(idx);
            Object parameter = values.get(idx);
            String value;
            if (parameter instanceof List) {
                StringBuilder sb = new StringBuilder();
                for (Object item : (List) parameter) {
                    if (sb.length() != 0) {
                        sb.append(",");
                    }
                    sb.append("\"").append(item).append("\"");
                }
                value = "[" + sb.toString() + "]";
            } else {
                value = parameter.toString();
            }
            byte[] encoded = coder.encode(value);
            encodedList.add(encoded);

            if (coder.dynamic) {
                staticSize += 32;
                dynamicSize += encoded.length;
            } else {
                staticSize += encoded.length;
            }
        }

        int offset = 0;
        int dynamicOffset = staticSize;

        byte[] data = new byte[staticSize + dynamicSize];

        for (int idx = 0; idx < codes.size(); idx++) {
            Coder coder = codes.get(idx);

            if (coder.dynamic) {
                System.arraycopy(new DataWord(dynamicOffset).getData(), 0, data, offset, 32);
                offset += 32;

                System.arraycopy(encodedList.get(idx), 0, data, dynamicOffset, encodedList.get(idx).length);
                dynamicOffset += encodedList.get(idx).length;
            } else {
                System.arraycopy(encodedList.get(idx), 0, data, offset, encodedList.get(idx).length);
                offset += encodedList.get(idx).length;
            }
        }

        return data;
    }

    public static String parseMethod(String methodSign, String params) {
        return parseMethod(methodSign, params, false);
    }

    public static String parseMethod(String methodSign, String input, boolean isHex) {
        byte[] selector = new byte[4];
        System.arraycopy(Hash.sha3(methodSign.getBytes()), 0, selector, 0, 4);
        System.out.println(methodSign + ":" + Hex.toHexString(selector));
        if (input.length() == 0) {
            return Hex.toHexString(selector);
        }
        if (isHex) {
            return Hex.toHexString(selector) + input;
        }
        byte[] encodedParms = encodeInput(methodSign, input);

        if (ByteUtil.isNullOrZeroArray(encodedParms)) return null;
        return Hex.toHexString(selector) + Hex.toHexString(encodedParms);
    }

    public static byte[] encodeInput(String methodSign, String input) {
        List items;
        //
        if (AddressUtil.isEmpty(methodSign, input)) return null;
        if (input.contains("[") || input.contains("]")) {
            items = parseInputToList_(input);
        } else {
            items = parseInputToList(input);
        }
        List<Coder> coders = new ArrayList<>();
        for (String s : getTypes(methodSign)) {
            Coder c = getParamCoder(s);
            coders.add(c);
        }

        return pack(coders, items);
    }
    public static byte[] encodeInputFromList(String methodSign, List<Object> input) {

        if (input == null || input.size() == 0) return null;
        List items = input;
        List<Coder> coders = new ArrayList<>();
        for (String s : getTypes(methodSign)) {
            Coder c = getParamCoder(s);
            coders.add(c);
        }
        return pack(coders, items);
    }

    //This method will have the problem of gson analysis of science and technology law
    //"[a,1111111111222222222223333333333]"this kind of data will throw error
    public static List parseInputToList_(String input) {
        input = "[" + input + "]";
        List items = new ArrayList<>();
        try {
            items = GsonFormatUtils.gsonToListFixDouble(input, List.class);
            return items;
        } catch (Exception e) {
            LogUtils.e(e);
        }
        return items;
    }

    public static List parseInputToList(String input) {
        List<Object> items = new ArrayList<>();
        try {
            if (input.contains(",")) {
                String[] split = input.split(",");
                for (String s : split) {
                    items.add(s);
                }
            } else {
                items.add(input);
            }

        } catch (Exception e) {
            LogUtils.e(e);
        }
        return items;

    }

    public static String parseMethod(String methodSign, List<Object> parameters) {
        String[] inputArr = new String[parameters.size()];
        int i = 0;
        for (Object parameter : parameters) {
            if (parameter instanceof List) {
                StringBuilder sb = new StringBuilder();
                for (Object item : (List) parameter) {
                    if (sb.length() != 0) {
                        sb.append(",");
                    }
                    sb.append("\"").append(item).append("\"");
                }
                inputArr[i++] = "[" + sb.toString() + "]";
            } else {
                inputArr[i++] = (parameter instanceof String) ? ("\"" + parameter + "\"") : ("" + parameter);
            }
        }
        return parseMethod(methodSign, StringUtils.join(inputArr, ','));
    }


    public static long decodeABI(String input) {
        byte[] data;
        data = Hex.decode(input);
        if (data == null)
            data = ByteUtil.EMPTY_BYTE_ARRAY;
        else if (data.length == 32)
            data = data;
        else if (data.length <= 32)
            System.arraycopy(data, 0, data, 32 - data.length, data.length);
        long longVal = 0;
        for (byte aData : data) {
            longVal = (longVal << 8) + (aData & 0xff);
        }
        return longVal;

    }

}
