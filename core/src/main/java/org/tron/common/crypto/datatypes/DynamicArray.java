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
package org.tron.common.crypto.datatypes;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Dynamic array type. */
public class DynamicArray<T extends Type> extends Array<T> {

    @Deprecated
    @SafeVarargs
    public DynamicArray(T... values) {
        super(inferElementType(Arrays.asList(values)), values);
    }

    @Deprecated
    public DynamicArray(List<T> values) {
        super(inferElementType(values), values);
    }

    @SuppressWarnings("unchecked")
    private static <T extends Type> Class<T> inferElementType(List<T> values) {
        if (values == null || values.isEmpty()) {
            throw new IllegalArgumentException(
                    "Cannot infer the element type of an empty array; "
                            + "use DynamicArray.empty(type) or the Class-based constructor");
        }
        T first = values.get(0);
        return StructType.class.isAssignableFrom(first.getClass())
                ? (Class<T>) first.getClass()
                : (Class<T>) AbiTypes.getType(first.getTypeAsString());
    }

    @Deprecated
    @SuppressWarnings("unchecked")
    private DynamicArray(String type) {
        super((Class<T>) AbiTypes.getType(type));
    }

    @Deprecated
    public static DynamicArray empty(String type) {
        return new DynamicArray(type);
    }

    public DynamicArray(Class<T> type, List<T> values) {
        super(type, values);
    }

    @Override
    public int bytes32PaddedLength() {
        return super.bytes32PaddedLength() + MAX_BYTE_LENGTH;
    }

    @Override
    public List<T> getValue() {
        // Read-only view (like StaticArray) to block post-construction tampering.
        return Collections.unmodifiableList(value);
    }

    @SafeVarargs
    public DynamicArray(Class<T> type, T... values) {
        super(type, values);
    }

    @Override
    public String getTypeAsString() {
        String type;
        // Handle dynamic array of zero length. This will fail if the dynamic array
        // is an array of structs.
        if (value.isEmpty()) {
            type = AbiTypes.getTypeAString(getComponentType());
        } else {
            if (StructType.class.isAssignableFrom(value.get(0).getClass())) {
                type = value.get(0).getTypeAsString();
            } else {
                type = AbiTypes.getTypeAString(getComponentType());
            }
        }
        return type + "[]";
    }
}
