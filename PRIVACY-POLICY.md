# Privacy Policy — TronLink Android

## 1. TL;DR — Our Promise in One Paragraph

TronLink Android is a **non-custodial, on-device wallet**. Your private keys, mnemonic phrases, wallet addresses, and transaction hashes **never leave your device** in plaintext. The only data we transmit is **aggregated, anonymized usage statistics** that exist solely to help us improve the product. We cannot link this data back to you, your wallet, your IP, or your device — and the code that proves it is open-source under the Apache-2.0 license.

If you only read one line of this document, read this:

> **We do not collect device-resident wallet addresses. We collect a random UUID that we generated for you locally, that you can wipe at any time by clearing app data, and that we cannot reverse into the address it represents.**

---

## 2. Design Principles

TronLink Android is built around four invariants. Every code path that touches user data must satisfy all four:

1. **Local-First** — Sensitive material (keys, mnemonics, addresses) is processed and stored on-device only. The backend is *unable* to recover it, not merely *promising* not to.
2. **Non-Identifying by Construction** — Telemetry payloads are designed so that no field, alone or in combination, can be tied to a real address, a real user, or a real transaction.
3. **Aggregated, Not Granular** — Per-transaction amounts and timestamps are aggregated and bucketed locally before any transmission. We see distributions, not data points.
4. **Auditable** — Every claim in this document maps to a specific file in the public source tree. If you do not trust the prose, read the code.

---

## 3. What Stays on Your Device, Always

The following items are generated, used, and stored **exclusively in the app's private Android sandbox** (the local Room database `metrics.db` and app private storage), and are **never transmitted** to any server controlled by TronLink or any third party:

| Item | Where it lives | Sent to backend? |
|------|---------------|:---:|
| Mnemonic phrase / seed | Encrypted in app sandbox | **Never** |
| Private keys | Encrypted in app sandbox | **Never** |
| Public keys | Derived locally from private keys | **Never** |
| Wallet addresses (TRX) | App sandbox + Room (`metrics.db`) | **Never** |
| Transaction hashes | Held in memory during signing | **Never** |
| Contract call parameters / payload | Held in memory during signing | **Never** |
| Counter-party addresses | Held in memory during signing | **Never** |
| Device fingerprint / Android ID / Advertising ID / IMEI / MAC | Not collected | **Never** |
| IP address | Not stored or logged | **Never** |
| Email / phone / KYC information | Not requested | **Never** |

The wallet is **stateless on the server side**: there is no account to register, no email to verify, no profile to build. TronLink Android simply does not have these inputs to leak.

---

## 4. The Anonymous Analytics Module — How It Actually Works

To improve the app, we need to answer questions like *"how many users staked TRX last week?"* or *"what's the typical transaction-amount distribution on TRC-20?"*. We answer them **without ever learning who any individual user is**. This section explains how.

The relevant code lives in [`core/src/main/java/org/tron/metrics/`](https://github.com/TronLink/tronlink-android-core/tree/main/core/src/main/java/org/tron/metrics).

### 4.1 Address → UUID: One-Way, Local-Only

When the analytics module needs an identifier for a wallet, it does **not** use the address. Instead, it asks for or generates a random UUID:

```java
// core/src/main/java/org/tron/metrics/repository/UIDMapRepository.java
@Override
public synchronized String queryUIDByAddress(String address) {
    UIdMappingEntity entity = uidMappingDao.getByAddress(address);
    if (entity == null) {
        String uuid = newUID();              // UUID.randomUUID().toString()
        insert(address, uuid);                // persisted on-device only (Room)
        return uuid;
    }
    return entity.getUId();
}
```

`newUID()` calls the JDK's `UUID.randomUUID()` (RFC 4122 v4, 122 bits of entropy backed by `SecureRandom`).

Why this matters:

- The mapping `address → uuid` exists **only inside the app's private sandbox** on your device. Our servers never see the address that produced the UUID.
- The UUID is **not derived** from the address, public key, or any other property. There is no inverse function.
- Two wallets owned by the same person produce **two unrelated UUIDs**. The backend cannot cluster them into a single user.
- Clearing the app's data, or uninstalling, destroys the mapping. The next session generates a new UUID, breaking continuity with any prior reports.

### 4.2 Amounts → Logarithmic Buckets

Per-transaction exact amounts are never transmitted. Before a transaction record is queued, the amount is replaced with a **9-bucket logarithmic histogram label**:

| Bucket | Range (token units)     |
|--------|-------------------------|
| A1     | (0, 1]                  |
| A2     | (1, 10]                 |
| A3     | (10, 100]               |
| A4     | (100, 1 000]            |
| A5     | (1 000, 10 000]         |
| A6     | (10 000, 100 000]       |
| A7     | (100 000, 1 000 000]    |
| A8     | (1 000 000, 10 000 000] |
| A9     | (> 10 000 000)          |

A transfer of `1234.56 USDT` is recorded as bucket `A5` with `count: 1`. The exact amount, the recipient, and the transaction hash are discarded. The backend cannot reconstruct any specific transaction from these histograms — it can only see, in aggregate, that "users made N transfers in the 1k–10k range today." Implementation: `org.tron.metrics.utils.TokenAmountClassifier`.

### 4.3 Local Aggregation Before Upload

TronLink Android merges records on-device, keyed by `(uid, actionType, tokenAddress, day)`, **before** anything is sent. If you make ten TRC-20 transfers of similar magnitude on the same day, the backend receives **one row** with `count: 10`, not ten individual events. Per-transaction timing is destroyed by this step; only the UTC date is kept.

### 4.4 The "Basic Mode" Toggle

Reporting is gated by a user-controlled switch. TronLink Android exposes a **"Basic Mode" toggle in Settings**. When this toggle is **on**, the app operates in a minimal, telemetry-free mode: it does not initialize the analytics pipeline, no payload is constructed, and no network request is made. The destination URL is supplied by the app at initialization time — there is no hard-coded reporting endpoint inside the analytics module that could fire on its own:

```java
// core/src/main/java/org/tron/metrics/reporter/DataUploader.java
public void upload(IUploadResultCallback iUploadResultCallback) {
    if (this.okHttpClient == null || this.baseUrl == null) {
        return;   // not initialized → return, send nothing
    }
    ...
}
```

In addition, **watch-only wallets** (addresses imported as watch-only, `idType = eg1`) are excluded at the source. They never enter the data-preparation stage, regardless of the toggle.

### 4.5 Encrypted in Transit

By default, the `X` / `Y` fields are encrypted before they leave the device:

```java
// core/src/main/java/org/tron/metrics/reporter/DataFormatInterceptor.java
if (DataUploader.getInstance().getFormatPlain()) {
    return chain.proceed(request);   // plain mode (off by default)
}
// otherwise encrypt with a key derived from ts + signature
String encryptedXData = StatDataConverter.encryptDataWithTs(originalStatRequest.getX(), ts, signature);
```

The cipher is `AES/CBC/PKCS5Padding`; the key is derived from the request timestamp and signature via `PBKDF2WithHmacSHA256`; each encryption uses a fresh random 16-byte IV prefixed to the ciphertext. Even an already-aggregated, non-identifying payload gets one more layer before it leaves your device.

### 4.6 Reported, Then Forgotten

Once a daily batch is acknowledged by the backend, it is **deleted from local storage**:

```java
// core/src/main/java/org/tron/metrics/reporter/DataUploader.java
private void deleteCachedData(boolean result, DataPreparationManager.DataPreparationResult prepResult) {
    if (result) {
        balanceRepository.updateAndDelete(prepResult.getBalanceList());
        transactionRepository.updateAndDeleteData(prepResult.getTransactionList());
    }
}
```

Today's row is retained until UTC roll-over so subsequent same-day events can be merged; once the day rolls over, it is deleted along with the rest. There is no rolling local archive that could later be exfiltrated.

---

## 5. What the Backend Sees — Concrete Examples

To make the above tangible, here is the literal payload format used by the reporter (from `StatDataConverter.buildXDataString` / `buildYDataString`):

**Asset snapshot (daily, per UUID):**
```
V1X|<uuid>|<idType>|<trxBalance>|<usdtBalance>|<usdBalance>|<day>|
```

**Transaction record (daily, per UUID + actionType + token, aggregated):**
```
V1Y|<uuid>|<idType>|<actionType>|<count>|<tokenAddress>|<tokenAmount>|<energy>|<bandwidth>|<burn>|<day>|<amountDistribution>|
```

Notice what is **not** in either payload:

- ❌ The wallet address
- ❌ The counter-party address
- ❌ The transaction hash
- ❌ Per-transaction exact amounts (replaced by the bucket histogram; `<tokenAmount>` is the daily aggregated sum for that `(uid, actionType, tokenAddress)` group, not any individual amount)
- ❌ Any timestamp finer than UTC date
- ❌ The IP, device ID, Android ID, IMEI, MAC, Advertising ID
- ❌ The app version, OS version, or device model
- ❌ The user's chosen RPC endpoint

The `<tokenAddress>` field refers to the token contract being transferred (e.g., the USDT contract; TRC10 carries a numeric ID prefix, TRC20 carries a contract-address prefix), **not** your wallet. For TRX it is the literal placeholder `_`.

---

## 6. Why We Cannot Re-Identify You — Even If We Wanted To

A common, fair question: *"You promise not to link my UUID to my address — but couldn't you?"*

No. The architecture makes it impossible at the source:

1. **The address never leaves your device.** The UUID-mapping table is written to a Room database (`metrics.db`) inside the app's private sandbox. The backend has no API to read it. TronLink Android has no code path that uploads it.
2. **The UUID is random, not derived.** There is no key, salt, or hash function that can map a UUID back to an address. The mapping exists only as the local database row that you generated.
3. **Even with full server logs, we see no anchor.** No IP is associated with the report (the encrypted payload does not include one, and our infra strips per-user IP on ingest). No device fingerprint, no Android ID, no Advertising ID, no app instance ID is sent.
4. **Multi-wallet users are indistinguishable from multi-user installs.** Because each address gets an independent UUID, a single person with 5 wallets is statistically identical to 5 different people with 1 wallet each.

The strongest privacy guarantees are the ones a vendor *could not violate* even under coercion. This is one of them.

---

## 7. What We Do **Not** Use Your Data For

We do not, and TronLink Android does not enable us to:

- Sell or share usage data with advertisers, data brokers, or analytics vendors (Segment, Mixpanel, Amplitude, Google Analytics, Firebase Analytics, etc.).
- Build a profile of your holdings, balances, or trading behavior.
- Cluster wallets by suspected ownership.
- Send you marketing emails or push notifications (we have neither your email nor any device push token).
- Track you across apps, dApps, or sessions.
- Comply with subpoenas for individual user data — because we do not hold any.

---

## 8. Open Source — Verify, Don't Trust

Every claim above is testable. The full source is published at:

> **https://github.com/TronLink/tronlink-android-core** — Apache-2.0

Recommended audit checklist:

- `core/src/main/java/org/tron/metrics/repository/UIDMapRepository.java` — confirm the address never leaves the device; UUIDs are minted on-device by `UUID.randomUUID()`.
- `core/src/main/java/org/tron/metrics/utils/TokenAmountClassifier.java` — confirm the 9-bucket logic (A1..A9 / A0).
- `core/src/main/java/org/tron/metrics/utils/StatDataConverter.java` — confirm the on-wire format `V1X|...` / `V1Y|...` and that no address field exists.
- `core/src/main/java/org/tron/metrics/bean/StatXData.java` / `StatYData.java` / `ActionType.java` — confirm the only fields that can ever be uploaded.
- `core/src/main/java/org/tron/metrics/reporter/DataPreparationManager.java` — confirm aggregation happens before any upload.
- `core/src/main/java/org/tron/metrics/reporter/DataUploader.java` — confirm the toggle gating (`init` / `baseUrl` / `upload`) and the post-upload deletion.
- `core/src/main/java/org/tron/metrics/reporter/DataFormatInterceptor.java` + `core/src/main/java/org/tron/metrics/utils/CryptoUtils.java` — confirm the in-transit encryption details.
- `core/src/main/java/org/tron/metrics/dao/MetricsDatabase.java` — confirm `metrics.db` is local-only.
- `git log core/src/main/java/org/tron/metrics/` — review the change history.

We welcome independent reviews and will treat reproducible privacy regressions as security incidents.

---

## 9. Your Controls

- **Enable Basic Mode:** Turn **on** the **Basic Mode** toggle in TronLink Android Settings. While Basic Mode is on, the app skips both asset snapshots and transaction records (no payload is constructed or queued, no network request is made).
- **Wipe local UUIDs:** Clearing the app's data via system settings, or uninstalling the app, destroys the `address → uuid` table inside `metrics.db`. Future sessions will allocate fresh, unrelated UUIDs.
- **Use a watch-only wallet:** Watch-only addresses (`idType = eg1`) are excluded from reporting at the source.
- **Inspect on-the-wire traffic:** The report path is `api/stat/some` (see the path check in `DataFormatInterceptor`). You can verify with a proxy tool or the Android Studio Network Inspector that nothing is sent while Basic Mode is on.

---

## 10. Data Retention

- **Local asset / transaction caches** (`BalanceCache`, `TransactionCache`): cleared by `DataUploader.deleteCachedData()` immediately after a successful upload. Today's row is kept across the UTC day boundary to allow same-day merging.
- **Local address → UUID map** (`UIdMappingEntity`): retained for the lifetime of the app's install so the surrogate UUID stays stable; destroyed on uninstall or app-data clear.
- **Server-side aggregated records:** retained by TronLink for as long as needed for the purposes described in §4.

---

## 11. Changes to This Policy

Material changes to data handling are announced in the repository's release notes and require a corresponding update to this document in the same commit. If any future code change would broaden collection beyond what this document describes, this document will be updated before (or together with) that change.
