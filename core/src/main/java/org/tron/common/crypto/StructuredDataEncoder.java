/*
 * Copyright 2019 Web3 Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.tron.common.crypto;

import static org.tron.common.crypto.Hash.sha3;
import static org.tron.common.crypto.Hash.sha3String;
import static org.tron.common.crypto.datatypes.Type.MAX_BYTE_LENGTH;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.ToNumberPolicy;
import com.google.gson.reflect.TypeToken;

import org.tron.common.bip32.Numeric;
import org.tron.common.crypto.datatypes.AbiTypes;
import org.tron.common.crypto.datatypes.Type;
import org.tron.common.utils.LogUtils;
import org.tron.walletserver.AddressUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


public class StructuredDataEncoder {
    public final StructuredData.EIP712Message jsonMessageObject;

    // Matches array declarations like arr[5][10], arr[][], arr[][34][], etc.
    // Doesn't match array declarations where there is a 0 in any dimension.
    // Eg- arr[0][5] is not matched.
    final String arrayTypeRegex = "^([a-zA-Z_$][a-zA-Z_$0-9]*)((\\[([1-9]\\d*)?\\])+)$";
    final Pattern arrayTypePattern = Pattern.compile(arrayTypeRegex);

    final String bytesTypeRegex = "^bytes[0-9][0-9]?$";
    final Pattern bytesTypePattern = Pattern.compile(bytesTypeRegex);

    private static class EIP712DomainDeserializer
            implements JsonDeserializer<StructuredData.EIP712Domain> {
        @Override
        public StructuredData.EIP712Domain deserialize(JsonElement json, java.lang.reflect.Type typeOfT,
                JsonDeserializationContext context) throws JsonParseException {
            JsonObject obj = json.getAsJsonObject();
            String name = optString(obj, "name");
            String version = optString(obj, "version");
            String chainId = optString(obj, "chainId");
            String verifyingContract = optString(obj, "verifyingContract");
            String salt = optString(obj, "salt");
            org.tron.common.crypto.datatypes.Address addressObj = verifyingContract != null
                    ? new org.tron.common.crypto.datatypes.Address(verifyingContract) : null;
            return new StructuredData.EIP712Domain(name, version, chainId, addressObj, salt);
        }

        private static String optString(JsonObject obj, String key) {
            return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString() : null;
        }
    }

    // This regex tries to extract the dimensions from the
    // square brackets of an array declaration using the ``Regex Groups``.
    // Eg- It extracts ``5, 6, 7`` from ``[5][6][7]``
    final String arrayDimensionRegex = "\\[([1-9]\\d*)?\\]";
    final Pattern arrayDimensionPattern = Pattern.compile(arrayDimensionRegex);

    // Fields of Entry Objects need to follow a regex pattern
    // Type Regex matches to a valid name or an array declaration.
    final String typeRegex = "^[a-zA-Z_$][a-zA-Z_$0-9]*(\\[([1-9]\\d*)*\\])*$";
    final Pattern typePattern = Pattern.compile(typeRegex);
    // Identifier Regex matches to a valid name, but can't be an array declaration.
    final String identifierRegex = "^[a-zA-Z_$][a-zA-Z_$0-9]*$";
    final Pattern identifierPattern = Pattern.compile(identifierRegex);
    private ArrayList<String> addressParseList = new ArrayList<>();

    public StructuredDataEncoder(String jsonMessageInString) throws IOException, IllegalArgumentException {
        // Parse String Message into object and validate
        this.jsonMessageObject = parseJSONMessage(jsonMessageInString);
    }

    private static byte[] convertArgToBytes(String inputValue) throws Exception {
        String hexValue = inputValue;
        if (!Numeric.containsHexPrefix(inputValue)) {
            BigInteger value;
            try {
                value = new BigInteger(inputValue);
            } catch (NumberFormatException e) {
                value = new BigInteger(inputValue, 16);
            }

            hexValue = Numeric.toHexStringNoPrefix(value.toByteArray());
            // fix sign condition
            if (hexValue.length() > 64 && hexValue.startsWith("00")) {
                hexValue = hexValue.substring(2);
            }
        }

        return Numeric.hexStringToByteArray(hexValue);
    }

    public ArrayList<String> getParseAddressList() {
        return addressParseList;
    }

    public Set<String> getDependencies(String primaryType) {
        // Find all the dependencies of a type
        HashMap<String, List<StructuredData.Entry>> types = jsonMessageObject.getTypes();
        Set<String> deps = new HashSet<>();

        if (!types.containsKey(primaryType)) {
            return deps;
        }

        List<String> remainingTypes = new ArrayList<>();
        remainingTypes.add(primaryType);

        while (remainingTypes.size() > 0) {
            String structName = remainingTypes.get(remainingTypes.size() - 1);
            remainingTypes.remove(remainingTypes.size() - 1);
            deps.add(structName);

            for (StructuredData.Entry entry : types.get(structName)) {
                String declarationFieldTypeName = entry.getType();
                String baseDeclarationTypeName =
                        arrayTypePattern.matcher(declarationFieldTypeName).find()
                                ? declarationFieldTypeName.substring(
                                0, declarationFieldTypeName.indexOf('['))
                                : declarationFieldTypeName;
                if (!types.containsKey(baseDeclarationTypeName)) {
                    // Don't expand on non-user defined types
                } else if (deps.contains(baseDeclarationTypeName)) {
                    // Skip types which are already expanded
                } else {
                    // Encountered a user defined type
                    remainingTypes.add(baseDeclarationTypeName);
                }
            }
        }

        return deps;
    }

    public String encodeStruct(String structName) {
        HashMap<String, List<StructuredData.Entry>> types = jsonMessageObject.getTypes();

        StringBuilder structRepresentation = new StringBuilder(structName + "(");
        for (StructuredData.Entry entry : types.get(structName)) {
            structRepresentation.append(String.format("%s %s,", entry.getType(), entry.getName()));
        }
        structRepresentation =
                new StringBuilder(
                        structRepresentation.substring(0, structRepresentation.length() - 1));
        structRepresentation.append(")");

        return structRepresentation.toString();
    }

    public String encodeType(String primaryType) {
        Set<String> deps = getDependencies(primaryType);
        deps.remove(primaryType);

        // Sort the other dependencies based on Alphabetical Order and finally add the primaryType
        List<String> depsAsList = new ArrayList<>(deps);
        Collections.sort(depsAsList);
        depsAsList.add(0, primaryType);

        StringBuilder result = new StringBuilder();
        for (String structName : depsAsList) {
            result.append(encodeStruct(structName));
        }

        return result.toString();
    }

    public byte[] typeHash(String primaryType) {
        return Numeric.hexStringToByteArray(sha3String(encodeType(primaryType)));
    }

    public List<Integer> getArrayDimensionsFromDeclaration(String declaration) {
        // Get the dimensions which were declared in Schema.
        // If any dimension is empty, then it's value is set to -1.
        Matcher arrayTypeMatcher = arrayTypePattern.matcher(declaration);
        arrayTypeMatcher.find();
        Matcher dimensionTypeMatcher = arrayDimensionPattern.matcher(declaration);
        List<Integer> dimensions = new ArrayList<>();
        while (dimensionTypeMatcher.find()) {
            String currentDimension = dimensionTypeMatcher.group(1);
            if (currentDimension == null) {
                dimensions.add(Integer.parseInt("-1"));
            } else {
                dimensions.add(Integer.parseInt(currentDimension));
            }
        }

        return dimensions;
    }

    @SuppressWarnings("unchecked")
    public List<Pair> getDepthsAndDimensions(Object data, int depth) {
        if (!(data instanceof List)) {
            // Nothing more to recurse, since the data is no more an array
            return new ArrayList<>();
        }

        List<Pair> list = new ArrayList<>();
        List<Object> dataAsArray = (List<Object>) data;
        list.add(new Pair(depth, dataAsArray.size()));
        for (Object subdimensionalData : dataAsArray) {
            list.addAll(getDepthsAndDimensions(subdimensionalData, depth + 1));
        }

        return list;
    }

    public List<Integer> getArrayDimensionsFromData(Object data) throws IllegalArgumentException {
        List<Pair> depthsAndDimensions = getDepthsAndDimensions(data, 0);
        // groupedByDepth has key as depth and value as List(pair(Depth, Dimension))
        Map<Object, List<Pair>> groupedByDepth =
                depthsAndDimensions.stream().collect(Collectors.groupingBy(Pair::getFirst));

        // depthDimensionsMap is aimed to have key as depth and value as List(Dimension)
        Map<Integer, List<Integer>> depthDimensionsMap = new HashMap<>();
        for (Map.Entry<Object, List<Pair>> entry : groupedByDepth.entrySet()) {
            List<Integer> pureDimensions = new ArrayList<>();
            for (Pair depthDimensionPair : entry.getValue()) {
                pureDimensions.add((Integer) depthDimensionPair.getSecond());
            }
            depthDimensionsMap.put((Integer) entry.getKey(), pureDimensions);
        }

        List<Integer> dimensions = new ArrayList<>();
        for (Map.Entry<Integer, List<Integer>> entry : depthDimensionsMap.entrySet()) {
            Set<Integer> setOfDimensionsInParticularDepth = new TreeSet<>(entry.getValue());
            if (setOfDimensionsInParticularDepth.size() != 1) {
                throw new IllegalArgumentException(
                        String.format(
                                "Depth %d of array data has more than one dimensions",
                                entry.getKey()));
            }
            dimensions.add(setOfDimensionsInParticularDepth.stream().findFirst().get());
        }

        return dimensions;
    }

    public List<Object> flattenMultidimensionalArray(Object data) {
        if (!(data instanceof List)) {
            return new ArrayList<Object>() {
                {
                    add(data);
                }
            };
        }

        List<Object> flattenedArray = new ArrayList<>();
        for (Object arrayItem : (List) data) {
            flattenedArray.addAll(flattenMultidimensionalArray(arrayItem));
        }

        return flattenedArray;
    }

    private byte[] convertToEncodedItem(String baseType, Object data) {
        byte[] hashBytes;
        try {
            if (baseType.toLowerCase(Locale.ROOT).startsWith("uint")
                    || baseType.toLowerCase(Locale.ROOT).startsWith("int")) {
                BigInteger value = convertToBigInt(data);
                if (value.signum() >= 0) {
                    hashBytes = Numeric.toBytesPadded(convertToBigInt(data), MAX_BYTE_LENGTH);
                } else {
                    byte signPadding = (byte) 0xff;
                    byte[] rawValue = convertToBigInt(data).toByteArray();
                    hashBytes = new byte[MAX_BYTE_LENGTH];
                    for (int i = 0; i < hashBytes.length; i++) {
                        hashBytes[i] = signPadding;
                    }
                    System.arraycopy(
                            rawValue,
                            0,
                            hashBytes,
                            MAX_BYTE_LENGTH - rawValue.length,
                            rawValue.length);
                }
            } else if (baseType.equals("string")) {
                hashBytes = Numeric.hexStringToByteArray(sha3String((String) data));
            } else if (baseType.equals("bytes")) {
                hashBytes = sha3(Numeric.hexStringToByteArray((String) data));
            } else if (baseType.equals("bool")) {
                BigInteger bi = new BigInteger((boolean) data ? "1" : "0");
                hashBytes = Numeric.toBytesPadded(bi, 32);
            } else if (bytesTypePattern.matcher(baseType).find()) {
                // Enforce the exact bytesN length up front. BytesN constructors reject
                // wrong lengths, but that failure used to be swallowed below, letting the
                // element contribute zero bytes to the array concatenation — so
                // [invalid, X] and [X] hashed identically (S-03).
                int expectedByteLength = Integer.parseInt(baseType.substring("bytes".length()));
                byte[] rawValue = Numeric.hexStringToByteArray((String) data);
                if (rawValue.length != expectedByteLength) {
                    throw new IllegalArgumentException(
                            String.format(
                                    "Type %s requires exactly %d bytes but data has %d",
                                    baseType, expectedByteLength, rawValue.length));
                }

                Class<Type> typeClazz = (Class<Type>) AbiTypes.getType(baseType);
                // Using the Reflection API to get the types of the parameters
                Constructor[] constructors = typeClazz.getConstructors();
                byte[] encodedItem = null;
                Exception lastConstructorFailure = null;
                for (Constructor constructor : constructors) {
                    // Check which constructor matches
                    try {
                        Class[] parameterTypes = constructor.getParameterTypes();
                        encodedItem =
                                Numeric.hexStringToByteArray(
                                        TypeEncoder.encode(
                                                typeClazz
                                                        .getDeclaredConstructor(parameterTypes)
                                                        .newInstance(rawValue)));
                        break;
                    } catch (IllegalArgumentException
                            | NoSuchMethodException
                            | InstantiationException
                            | IllegalAccessException
                            | InvocationTargetException e) {
                        // Constructor didn't match or rejected the value; try the next one.
                        lastConstructorFailure = e;
                    }
                }
                if (encodedItem == null) {
                    // Never fall back to an empty encoding: a zero-byte element makes
                    // distinct arrays concatenate (and hash) to the same value.
                    throw new IllegalArgumentException(
                            "Failed to construct " + baseType + " from provided data",
                            lastConstructorFailure);
                }
                hashBytes = encodedItem;
            } else {
                byte[] b = convertArgToBytes((String) data);
                BigInteger bi = new BigInteger(1, b);
                hashBytes = Numeric.toBytesPadded(bi, 32);
            }
        } catch (Exception e) {
            LogUtils.e(e);
            // Do not fall back to empty bytes: that would let a malformed/failed field be
            // signed over a hash built from incomplete data. Abort so the caller (which
            // already handles RuntimeException from hashStructuredData) cancels signing.
            throw new IllegalArgumentException("Failed to encode EIP-712 item: " + baseType, e);
        }

        return hashBytes;
    }

    private List<Object> getArrayItems(StructuredData.Entry field, Object value) {
        List<Integer> expectedDimensions = getArrayDimensionsFromDeclaration(field.getType());
        // This function will itself give out errors in case
        // that the data is not a proper array
        List<Integer> dataDimensions = getArrayDimensionsFromData(value);

        final String format =
                String.format(
                        "Array Data %s has dimensions %s, " + "but expected dimensions are %s",
                        value.toString(), dataDimensions.toString(), expectedDimensions.toString());
        if (expectedDimensions.size() != dataDimensions.size()) {
            // Ex: Expected a 3d array, but got only a 2d array
            throw new IllegalArgumentException(format);
        }
        for (int i = 0; i < expectedDimensions.size(); i++) {
            if (expectedDimensions.get(i) == -1) {
                // Skip empty or dynamically declared dimensions
                continue;
            }
            if (!expectedDimensions.get(i).equals(dataDimensions.get(i))) {
                throw new IllegalArgumentException(format);
            }
        }

        return flattenMultidimensionalArray(value);
    }

    @SuppressWarnings("unchecked")
    public byte[] encodeData(String primaryType, Map<String, Object> data)
            throws IllegalArgumentException {
        HashMap<String, List<StructuredData.Entry>> types = jsonMessageObject.getTypes();

        List<String> encTypes = new ArrayList<>();
        List<Object> encValues = new ArrayList<>();

        // Add typehash
        encTypes.add("bytes32");
        encValues.add(typeHash(primaryType));

        // Add field contents
        for (StructuredData.Entry field : types.get(primaryType)) {
            Object value = data.get(field.getName());

            if (value == null) continue;

            if (field.getType().equals("string")) {
                encTypes.add("bytes32");
                byte[] hashedValue = Numeric.hexStringToByteArray(sha3String((String) value));
                encValues.add(hashedValue);
            } else if (field.getType().equals("bytes")) {
                encTypes.add(("bytes32"));
                encValues.add(sha3(Numeric.hexStringToByteArray((String) value)));
            } else if (types.containsKey(field.getType())) {
                // User Defined Type
                byte[] hashedValue =
                        sha3(encodeData(field.getType(), (Map<String, Object>) value));
                encTypes.add("bytes32");
                encValues.add(hashedValue);
            } else if (bytesTypePattern.matcher(field.getType()).find()) {
                encTypes.add(field.getType());
                encValues.add(Numeric.hexStringToByteArray((String) value));
            } else if (arrayTypePattern.matcher(field.getType()).find()) {
                String baseTypeName = field.getType().substring(0, field.getType().indexOf('['));
                ArrayList<Object> objects = new ArrayList<>();
                if (baseTypeName.equals("address") && value instanceof List) {
                    ArrayList<String> arrayList = (ArrayList) value;
                    arrayList.stream().forEach(addressPre -> {
                        if ((addressPre).startsWith("41")) {
                            addressParseList.add(addressPre);
                        }

                        objects.add(AddressUtil.replace41Address(addressPre));
                    });
                    value = objects;
                }
                List<Object> arrayItems = getArrayItems(field, value);
                ByteArrayOutputStream concatenatedArrayEncodingBuffer = new ByteArrayOutputStream();

                for (Object arrayItem : arrayItems) {
                    byte[] arrayItemEncoding;
                    if (types.containsKey(baseTypeName)) {
                        arrayItemEncoding =
                                sha3(
                                        encodeData(
                                                baseTypeName,
                                                (Map<String, Object>)
                                                        arrayItem)); // need to hash each user type
                        // before adding
                    } else {
                        arrayItemEncoding =
                                convertToEncodedItem(
                                        baseTypeName,
                                        arrayItem); // add raw item, packed to 32 bytes
                    }

                    concatenatedArrayEncodingBuffer.write(
                            arrayItemEncoding, 0, arrayItemEncoding.length);
                }

                byte[] concatenatedArrayEncodings = concatenatedArrayEncodingBuffer.toByteArray();
                byte[] hashedValue = sha3(concatenatedArrayEncodings);
                encTypes.add("bytes32");
                encValues.add(hashedValue);
            } else if (field.getType().startsWith("uint") || field.getType().startsWith("int") || field.getType().equals("trcToken")) {
                encTypes.add(field.getType());
                // Convert to BigInteger for ABI constructor compatibility. Do NOT fall back to the
                // raw value on failure: that would let a malformed numeric field be signed over a
                // hash built from incorrect data. Abort instead, consistent with
                // convertToEncodedItem above, so the caller cancels signing.
                try {
                    encValues.add(convertToBigInt(value));
                } catch (NumberFormatException | NullPointerException e) {
                    LogUtils.e(e);
                    throw new IllegalArgumentException(
                            "Failed to encode EIP-712 numeric field of type " + field.getType(), e);
                }
            } else if (field.getType().equals("address")) {
                if (((String) value).startsWith("41")) {
                    addressParseList.add((String) value);
                }
                // no need replace, Address object will remove it auto
                // to avoid multi replace occurs in case of 41415Cb7E83668D78451A236c86DE505D5FF5024bD
                // String address0x = StringTronUtil.replace41Address((String) value);
                String address0x = (String) value;
                encTypes.add(field.getType());
                encValues.add(address0x);
            } else {
                encTypes.add(field.getType());
                encValues.add(value);
            }
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (int i = 0; i < encTypes.size(); i++) {
            Class<Type> typeClazz = (Class<Type>) AbiTypes.getType(encTypes.get(i));

            boolean atleastOneConstructorExistsForGivenParametersType = false;
            // Using the Reflection API to get the types of the parameters
            Constructor[] constructors = typeClazz.getConstructors();
            for (Constructor constructor : constructors) {
                // Check which constructor matches
                try {
                    Class[] parameterTypes = constructor.getParameterTypes();
                    byte[] temp =
                            Numeric.hexStringToByteArray(
                                    TypeEncoder.encode(
                                            typeClazz
                                                    .getDeclaredConstructor(parameterTypes)
                                                    .newInstance(encValues.get(i))));
                    baos.write(temp, 0, temp.length);
                    atleastOneConstructorExistsForGivenParametersType = true;
                    break;
                } catch (IllegalArgumentException
                        | NoSuchMethodException
                        | InstantiationException
                        | IllegalAccessException
                        | InvocationTargetException ignored) {
                }
            }

            if (!atleastOneConstructorExistsForGivenParametersType) {
                throw new IllegalArgumentException(
                        String.format(
                                "Received an invalid argument for which no constructor"
                                        + " exists for the ABI Class %s",
                                typeClazz.getSimpleName()));
            }
        }

        return baos.toByteArray();
    }

    private BigInteger convertToBigInt(Object value)
            throws NumberFormatException, NullPointerException {
        if (value.toString().startsWith("0x")) {
            return Numeric.toBigInt(value.toString());
        } else {
            return new BigInteger(value.toString());
        }
    }

    public byte[] hashMessage(String primaryType, Map<String, Object> data)
            throws IllegalArgumentException {
        return sha3(encodeData(primaryType, data));
    }

    public byte[] hashMessage() throws IllegalArgumentException {
        byte[] dataHash =
                hashMessage(
                        jsonMessageObject.getPrimaryType(),
                        (Map<String, Object>) jsonMessageObject.getMessage());
        return dataHash;
    }

    @SuppressWarnings("unchecked")
    public byte[] hashDomain() throws IllegalArgumentException {
        StructuredData.EIP712Domain domain = jsonMessageObject.getDomain();
        HashMap<String, Object> data = new HashMap<>();
        if (domain.getName() != null) data.put("name", domain.getName());
        if (domain.getVersion() != null) data.put("version", domain.getVersion());
        if (domain.getChainId() != null) data.put("chainId", domain.getChainId().getValue());
        if (domain.getVerifyingContract() != null)
            data.put("verifyingContract", domain.getVerifyingContract().getValue());
        if (domain.getSalt() != null) data.put("salt", domain.getSalt());
        boolean hasTip712Domain = jsonMessageObject.getTypes().containsKey("TIP712Domain");
        return sha3(encodeData(hasTip712Domain ? "TIP712Domain" : "EIP712Domain", data));
    }

    public void validateStructuredData(StructuredData.EIP712Message jsonMessageObject)
            throws IllegalArgumentException {
        for (String structName : jsonMessageObject.getTypes().keySet()) {
            List<StructuredData.Entry> fields = jsonMessageObject.getTypes().get(structName);
            for (StructuredData.Entry entry : fields) {
                if (!identifierPattern.matcher(entry.getName()).find()) {
                    // raise Error
                    throw new IllegalArgumentException(
                            String.format(
                                    "Invalid Identifier %s in %s", entry.getName(), structName));
                }
                if (!typePattern.matcher(entry.getType()).find()) {
                    // raise Error
                    throw new IllegalArgumentException(
                            String.format("Invalid Type %s in %s", entry.getType(), structName));
                }
            }
        }
    }

    public StructuredData.EIP712Message parseJSONMessage(String jsonMessageInString)
            throws IOException, IllegalArgumentException {
        // LAZILY_PARSED_NUMBER preserves uint256 precision when dapps send numeric
        // literals (e.g. {"amount": 115792089237316195423570985008687907853269984665640564039457584007913129639935})
        // instead of strings — Long/Double would silently truncate.
        Gson gson = new GsonBuilder()
            .registerTypeAdapter(StructuredData.EIP712Domain.class, new EIP712DomainDeserializer())
            .setObjectToNumberStrategy(ToNumberPolicy.LAZILY_PARSED_NUMBER)
            .create();

        // convert JSON string to EIP712Message object
        StructuredData.EIP712Message tempJSONMessageObject =
                gson.fromJson(jsonMessageInString, StructuredData.EIP712Message.class);
        validateStructuredData(tempJSONMessageObject);

        return tempJSONMessageObject;
    }

    public StructuredData.EIP712Domain getDomain() {
        return jsonMessageObject.getDomain();
    }

    public Object getMessage() {
        return jsonMessageObject.getMessage();
    }

    @SuppressWarnings("unchecked")
    public byte[] getStructuredData() throws IllegalArgumentException {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        final String messagePrefix = "\u0019\u0001";
        byte[] prefix = messagePrefix.getBytes();
        baos.write(prefix, 0, prefix.length);

        byte[] domainHash = hashDomain();
        baos.write(domainHash, 0, domainHash.length);

        byte[] dataHash =
                hashMessage(
                        jsonMessageObject.getPrimaryType(),
                        (Map<String, Object>) jsonMessageObject.getMessage());
        baos.write(dataHash, 0, dataHash.length);

        return baos.toByteArray();
    }

    @SuppressWarnings("unchecked")
    public byte[] hashStructuredData() throws IllegalArgumentException {
        return sha3(getStructuredData());
    }
}
