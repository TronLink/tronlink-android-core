package org.tron.common.crypto.datatypes.generated;

import org.tron.common.crypto.datatypes.StaticArray;
import org.tron.common.crypto.datatypes.Type;

import java.util.List;

/**
 * Auto generated code.
 * <p><strong>Do not modifiy!</strong>
 * <p>Please use org.web3j.codegen.AbiTypesGenerator in the 
 * <a href="https://github.com/web3j/web3j/tree/master/codegen">codegen module</a> to update.
 */
public class StaticArray16<T extends Type> extends StaticArray<T> {
    @Deprecated
    public StaticArray16(List<T> values) {
        super(16, values);
    }

    @Deprecated
    @SafeVarargs
    public StaticArray16(T... values) {
        super(16, values);
    }

    public StaticArray16(Class<T> type, List<T> values) {
        super(type, 16, values);
    }

    @SafeVarargs
    public StaticArray16(Class<T> type, T... values) {
        super(type, 16, values);
    }
}
