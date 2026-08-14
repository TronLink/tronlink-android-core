package org.tron.common.utils;


import android.text.TextUtils;

import java.math.BigDecimal;
import java.math.BigInteger;

public class DecimalUtils {
    
    public static String toString(BigDecimal bigDecimalCount) {
        return bigDecimalCount.stripTrailingZeros().toPlainString();
    }

    public static String toString(Object bigDecimalCount) {
        return  toBigDecimal(bigDecimalCount).stripTrailingZeros().toPlainString();
    }

    public static BigDecimal toBigDecimal(Object object) {
        try {
            if (object instanceof BigDecimal)
                return (BigDecimal) object;
            else if (object instanceof String) {
                if (TextUtils.isEmpty((String) object)) {
                    return new BigDecimal(0);
                }
                return new BigDecimal((String) object);
            } else if (object instanceof Double)
                return BigDecimal.valueOf((Double) object);
            else if (object instanceof Float)
                return new BigDecimal(String.valueOf(object));
            else if (object instanceof Integer)
                return new BigDecimal((int) object);
            else if (object instanceof BigInteger)
                return new BigDecimal((BigInteger) object);
            else if (object instanceof Long)
                return BigDecimal.valueOf((Long) object);
            else
                return new BigDecimal(0);
        } catch (Throwable e) {
            // Parsing failed: log it so an invalid amount is not silently treated as 0.
            // Callers in amount-sensitive paths must not assume the returned 0 means a real
            // zero value when a malformed input was supplied.
            LogUtils.e(e);
            return BigDecimal.valueOf(0);
        }
    }

}
