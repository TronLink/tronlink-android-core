# tronlink-android-core

TronLink Wallet is a decentralized non-custodial wallet.TronLink-Core is the core module of TronLink Wallet, which provides core functions such as Create Wallet, Get Address and Sign Transaction.

## Privacy

TronLink Android only transmits aggregated, anonymized usage statistics. **Wallet addresses, private keys, mnemonics, transaction hashes, counter-parties, IPs, and device identifiers are never transmitted.** The backend receives only opaque per-address UUIDs minted on-device, plus same-day aggregated counts and 9-bucket logarithmic amount histograms — individual transactions cannot be reconstructed.

Reporting is gated by an in-app **Basic Mode** toggle in TronLink Android Settings. When Basic Mode is **on**, no payload is built and no request is made.

For full details — what is collected, what is never collected, how anonymization / aggregation / encryption work, retention, and your controls — see [PRIVACY-POLICY.md](./PRIVACY-POLICY.md).


## Requirements

- Android 21+
- Java 1.8+

## How to use

Add the JitPack maven repository.

```
maven { url "https://jitpack.io"  }
```

Add dependency.

```
implementation 'com.github.TronLink:tronlink-android-core:1.0.2@aar'
```

## Integrity Check

tronlink-android-core.aar is signed by the gpg key as below. You can use the gpg public key to verify the integrity of the officially released core library.

  ```
  pub: 7B910EA80207596075E6D7BA5D34F7A6550473BA
  uid: build_tronlink <build@tronlink.org>
  ```

 For example:

  ```
  #gpg --verify tronlink-android-core-xxx.aar.asc tronlink-android-core-xxx.aar
  gpg: Signature made 一  7/29 16:03:14 2024 CST
  gpg:                using RSA key 7B910EA80207596075E6D7BA5D34F7A6550473BA
  gpg: Good signature from "build_tronlink <build@tronlink.org>"
  ```

## Demo

- [Create new wallet](./core/src/test/java/org/tron/WalletCoreUnitTest.java)
- [Sign transaction](./core/src/test/java/org/tron/TransactionCoreUnitTest.java)
- [Sign message](./core/src/test/java/org/tron/TransactionCoreUnitTest.java)
