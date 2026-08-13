package org.tron.walletserver;

import androidx.annotation.Nullable;

import org.tron.common.utils.GsonFormatUtils;

import org.tron.common.utils.LogUtils;

import java.io.Serializable;
import java.util.Objects;

import lombok.Data;

/**
 * purpose      default44 (Documentation source from  BIP43)
 * coinType     TRON default 195
 * account      default 0
 * change       default 0
 * accountIndex default 0
 */
@Data
public class WalletPath implements Serializable {
    private static final long serialVersionUID = 95504495L;
    private static final int MAX_CHILD_INDEX = 0x7fffffff;
    public int purpose = 44;
    public int coinType = 195;
    public int account;
    public int change;
    public int accountIndex;

    public static WalletPath createDefault() {
        return createDefault(0);
    }

    public static WalletPath createDefault(int accountIndex) {
        WalletPath ret = new WalletPath();
        ret.account = 0;
        ret.change = 0;
        ret.accountIndex = accountIndex;
        return ret;
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof WalletPath)) return false;
        WalletPath w = (WalletPath) other;
        return purpose == w.purpose &&
                coinType == w.coinType &&
                accountIndex == w.accountIndex &&
                account == w.account &&
                change == w.change;
    }

    @Override
    public int hashCode() {
        return Objects.hash(purpose, coinType, accountIndex, account, change);
    }

    public static String buildPathString(@Nullable WalletPath wp) {
        if (wp == null) return AddressUtil.EMPTY_STRING;
        return "m/" +
                buildPath(wp);
    }

    public static String buildPath(@Nullable String pathStr) {
        if (AddressUtil.isEmpty(pathStr)) return "";
        return buildPath(parseWalletPath(pathStr));
    }

    private static WalletPath parseWalletPath(String pathStr) {
        WalletPath walletPath;
        try {
            walletPath = GsonFormatUtils.gsonToBean(pathStr, WalletPath.class);
        } catch (RuntimeException e) {
            LogUtils.e(e);
            throw new IllegalArgumentException("Failed to parse wallet path", e);
        }
        if (walletPath == null) {
            throw new IllegalArgumentException("Failed to parse wallet path");
        }
        validate(walletPath);
        return walletPath;
    }

    public static String buildPath(@Nullable WalletPath wp) {
        if (wp == null) return AddressUtil.EMPTY_STRING;
        validate(wp);
        return wp.purpose +
                "'/" +
                wp.coinType +
                "'/" +
                wp.account +
                "'/" +
                wp.change +
                "/" +
                wp.accountIndex;
    }

    public static WalletPath buildWalletPath(String mnemonicPath) {
        if (AddressUtil.isEmpty(mnemonicPath)) {
            return new WalletPath();
        }
        return parseWalletPath(mnemonicPath);
    }

    public static void validate(WalletPath path) {
        if (path == null) {
            throw new IllegalArgumentException("Wallet path must not be null");
        }
        validate(path.purpose, path.coinType, path.account, path.change, path.accountIndex);
    }

    public static void validate(int purpose, int coinType, int account, int change, int accountIndex) {
        requireChildIndex("purpose", purpose);
        requireChildIndex("coinType", coinType);
        requireChildIndex("account", account);
        if (change != 0 && change != 1) {
            throw new IllegalArgumentException("Wallet path change must be 0 or 1");
        }
        requireChildIndex("accountIndex", accountIndex);
    }

    private static void requireChildIndex(String name, int value) {
        if (value < 0 || value > MAX_CHILD_INDEX) {
            throw new IllegalArgumentException("Wallet path " + name + " is out of range");
        }
    }


}
