/*
 * java-tron is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * java-tron is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.tron.common.utils;

import static org.tron.common.crypto.Hash.sha256;

import com.google.common.primitives.Bytes;
import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.util.encoders.Hex;
import org.tron.api.GrpcAPI;
import org.tron.common.bip32.ECKeyPair;
import org.tron.common.bip32.Numeric;
import org.tron.common.bip32.Sign;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.Hash;
import org.tron.common.exceptions.ContractValidateException;
import org.tron.common.exceptions.ZksnarkException;
import org.tron.common.utils.abi.TronException;
import org.tron.config.Parameter;
import org.tron.protos.Protocol;
import org.tron.protos.Protocol.Transaction;
import org.tron.protos.Protocol.Transaction.Contract;
import org.tron.protos.contract.AccountContract;
import org.tron.protos.contract.AssetIssueContractOuterClass;
import org.tron.protos.contract.BalanceContract;
import org.tron.protos.contract.ExchangeContract;
import org.tron.protos.contract.ProposalContract;
import org.tron.protos.contract.ShieldContract;
import org.tron.protos.contract.SmartContractOuterClass;
import org.tron.protos.contract.StorageContract;
import org.tron.protos.contract.VoteAssetContractOuterClass;
import org.tron.protos.contract.WitnessContract;
import org.tron.walletserver.AddressUtil;

import java.util.Arrays;
import java.util.List;


public class TransactionUtils {


    /**
     * Obtain a data bytes after removing the id and SHA-256(data)
     *
     * @param transaction {@link Transaction} transaction
     * @return byte[] the hash of the transaction's data bytes which have no id
     */
    public static String getHash(Transaction transaction) {
        return Hex.toHexString(Hash.sha256(transaction.getRawData().toByteArray()));
    }

    //---------------
    public static <T extends com.google.protobuf.MessageLite> T unpackContract(
            Contract contract,
            Class<T> clazz)
            throws InvalidProtocolBufferException {

        T defaultInstance =
                com.google.protobuf.Internal.getDefaultInstance(clazz);
        T result = (T) defaultInstance.getParserForType()
                .parseFrom(contract.getParameter().getValue());
        return result;
    }
    //---------------


    public static Transaction setReference(Transaction transaction, Protocol.Block newestBlock) {
        long blockHeight = newestBlock.getBlockHeader().getRawData().getNumber();
        byte[] blockHash = getBlockHash(newestBlock).getBytes();
        byte[] refBlockNum = ByteArray.fromLong(blockHeight);
        Transaction.raw rawData = transaction.getRawData().toBuilder()
                .setRefBlockHash(ByteString.copyFrom(ByteArray.subArray(blockHash, 8, 16)))
                .setRefBlockBytes(ByteString.copyFrom(ByteArray.subArray(refBlockNum, 6, 8)))
                .build();
        return transaction.toBuilder().setRawData(rawData).build();
    }

    public static Sha256Hash getBlockHash(Protocol.Block block) {
        return Sha256Hash.of(block.getBlockHeader().getRawData().toByteArray());
    }

    public static String getTransactionHash(Transaction transaction) {
        String txid = ByteArray.toHexString(Sha256Hash.hash(transaction.getRawData().toByteArray()));
        return txid;
    }

    public static String getShieldTransactionHash(Transaction transaction, String tokenId)
            throws ContractValidateException, ZksnarkException {

        List<Contract> contract = transaction.getRawData().getContractList();
        if (contract == null || contract.size() == 0) {
            throw new ContractValidateException("Contract is null");
        }
        Contract.ContractType contractType = contract.get(0).getType();
        if (contractType != Contract.ContractType.ShieldedTransferContract) {
            throw new ContractValidateException("Not a shielded transaction");
        }

        byte[] transactionHash = getShieldTransactionHashIgnoreTypeException(transaction, tokenId);
        return ByteArray.toHexString(transactionHash);
    }

    public static byte[] getOwner(Contract contract) {
        ByteString owner;
        try {
            switch (contract.getType()) {
                case AccountCreateContract:
                    owner = unpackContract(contract, AccountContract.AccountCreateContract.class).getOwnerAddress();
                    break;
                case TransferContract:
                    owner = unpackContract(contract, BalanceContract.TransferContract.class).getOwnerAddress();
                    break;
                case TransferAssetContract:
                    owner = unpackContract(contract, AssetIssueContractOuterClass.TransferAssetContract.class).getOwnerAddress();
                    break;
                case VoteAssetContract:
                    owner = unpackContract(contract, VoteAssetContractOuterClass.VoteAssetContract.class).getOwnerAddress();
                    break;
                case VoteWitnessContract:
                    owner = unpackContract(contract, WitnessContract.VoteWitnessContract.class).getOwnerAddress();
                    break;
                case WitnessCreateContract:
                    owner = unpackContract(contract, WitnessContract.WitnessCreateContract.class).getOwnerAddress();
                    break;
                case AssetIssueContract:
                    owner = unpackContract(contract, AssetIssueContractOuterClass.AssetIssueContract.class).getOwnerAddress();
                    break;
                case WitnessUpdateContract:
                    owner = unpackContract(contract, WitnessContract.WitnessUpdateContract.class).getOwnerAddress();
                    break;
                case ParticipateAssetIssueContract:
                    owner = unpackContract(contract, AssetIssueContractOuterClass.ParticipateAssetIssueContract.class).getOwnerAddress();
                    break;
                case AccountUpdateContract:
                    owner = unpackContract(contract, AccountContract.AccountUpdateContract.class).getOwnerAddress();
                    break;
                case FreezeBalanceContract:
                    owner = unpackContract(contract, BalanceContract.FreezeBalanceContract.class).getOwnerAddress();
                    break;
                case FreezeBalanceV2Contract:
                    owner = unpackContract(contract, BalanceContract.FreezeBalanceV2Contract.class).getOwnerAddress();
                    break;
                case UnfreezeBalanceContract:
                    owner = unpackContract(contract, BalanceContract.UnfreezeBalanceContract.class).getOwnerAddress();
                    break;
                case UnfreezeBalanceV2Contract:
                    owner = unpackContract(contract, BalanceContract.UnfreezeBalanceV2Contract.class).getOwnerAddress();
                    break;
                case UnfreezeAssetContract:
                    owner = unpackContract(contract, AssetIssueContractOuterClass.UnfreezeAssetContract.class).getOwnerAddress();
                    break;
                case WithdrawBalanceContract:
                    owner = unpackContract(contract, BalanceContract.WithdrawBalanceContract.class).getOwnerAddress();
                    break;
                case UpdateAssetContract:
                    owner = unpackContract(contract, AssetIssueContractOuterClass.UpdateAssetContract.class).getOwnerAddress();
                    break;
                case CreateSmartContract:
                    owner = unpackContract(contract, SmartContractOuterClass.CreateSmartContract.class).getOwnerAddress();
                    break;
                case TriggerSmartContract:
                    owner = unpackContract(contract, SmartContractOuterClass.TriggerSmartContract.class).getOwnerAddress();
                    break;
                case AccountPermissionUpdateContract:
                    owner = unpackContract(contract, AccountContract.AccountPermissionUpdateContract.class).getOwnerAddress();
                    break;
                case UpdateBrokerageContract:
                    owner = unpackContract(contract, StorageContract.UpdateBrokerageContract.class).getOwnerAddress();
                    break;
                case ProposalCreateContract:
                    owner = unpackContract(contract, ProposalContract.ProposalCreateContract.class).getOwnerAddress();
                    break;
                case ProposalDeleteContract:
                    owner = unpackContract(contract, ProposalContract.ProposalDeleteContract.class).getOwnerAddress();
                    break;
                case ProposalApproveContract:
                    owner = unpackContract(contract, ProposalContract.ProposalApproveContract.class).getOwnerAddress();
                    break;
                case DelegateResourceContract:
                    owner = unpackContract(contract, BalanceContract.DelegateResourceContract.class).getOwnerAddress();
                    break;
                case UnDelegateResourceContract:
                    owner = unpackContract(contract, BalanceContract.UnDelegateResourceContract.class).getOwnerAddress();
                    break;
                case WithdrawExpireUnfreezeContract:
                    owner = unpackContract(contract, BalanceContract.WithdrawExpireUnfreezeContract.class).getOwnerAddress();
                    break;
                case CancelAllUnfreezeV2Contract:
                    owner = unpackContract(contract, BalanceContract.CancelAllUnfreezeV2Contract.class).getOwnerAddress();
                    break;
                case ExchangeTransactionContract:
                    owner = unpackContract(contract, ExchangeContract.ExchangeTransactionContract.class).getOwnerAddress();
                    break;
                case ExchangeWithdrawContract:
                    owner = unpackContract(contract, ExchangeContract.ExchangeWithdrawContract.class).getOwnerAddress();
                    break;
                case ExchangeInjectContract:
                    owner = unpackContract(contract, ExchangeContract.ExchangeInjectContract.class).getOwnerAddress();
                    break;
                case ExchangeCreateContract:
                    owner = unpackContract(contract, ExchangeContract.ExchangeCreateContract.class).getOwnerAddress();
                    break;
                case UpdateEnergyLimitContract:
                    owner = unpackContract(contract, SmartContractOuterClass.UpdateEnergyLimitContract.class).getOwnerAddress();
                    break;
                case ClearABIContract:
                    owner = unpackContract(contract, SmartContractOuterClass.ClearABIContract.class).getOwnerAddress();
                    break;
                case SetAccountIdContract:
                    owner = unpackContract(contract, AccountContract.SetAccountIdContract.class).getOwnerAddress();
                    break;
                case UpdateSettingContract:
                    owner = unpackContract(contract, SmartContractOuterClass.UpdateSettingContract.class).getOwnerAddress();
                    break;

                default:
                    return null;
            }
            return owner.toByteArray();
        } catch (Exception ex) {
            LogUtils.e(ex);
            return null;
        }
    }

    public static String getBase64FromByteString(ByteString sign) {
        try {
            // Expects a 65-byte signature: r (0..32) | s (32..64) | v (64).
            byte[] r = sign.substring(0, 32).toByteArray();
            byte[] s = sign.substring(32, 64).toByteArray();
            byte v = sign.byteAt(64);
            if (v < 27) {
                v += 27; //revId -> v
            }
            ECKey.ECDSASignature signature = ECKey.ECDSASignature.fromComponents(r, s, v);
            return signature.toBase64();
        } catch (Exception e) {
            LogUtils.e(e);
            return "";
        }
    }

    /**
     * @param transaction
     * @param myKey
     * @return
     */
    public static Transaction sign(Transaction transaction, ECKey myKey) {
        // Returning an unsigned transaction silently is indistinguishable from
        // success for callers; fail fast like the chainId overload does.
        if (transaction == null) {
            throw new IllegalArgumentException("Transaction required for sign");
        }
        if (myKey == null) {
            throw new IllegalArgumentException("ECKey required for sign");
        }
        Transaction.Builder transactionBuilderSigned = transaction.toBuilder();
        byte[] hash = sha256(transaction.getRawData().toByteArray());
        // Sign the rawData hash once. Looping over the contract list signed the same hash with the
        // same key repeatedly, producing duplicate signatures for multi-contract transactions.
        ECKey.ECDSASignature signature = myKey.sign(hash);
        ByteString bsSign = ByteString.copyFrom(signature.toByteArray());
        transactionBuilderSigned.addSignature(
                bsSign);//Each contract may be signed with a different private key in the future.

        transaction = transactionBuilderSigned.build();
        return transaction;
    }


    public static Transaction sign(Transaction transaction, ECKey myKey, byte[] chainId,
                                   boolean isMainChain) {
        if (transaction == null) return null;
        if (myKey == null) {
            return null;
        }
        Transaction.Builder transactionBuilderSigned = transaction.toBuilder();
        byte[] hash = Sha256Hash.hash(transaction.getRawData().toByteArray());
        //TODO Temporary add，3。3。0 changed to throw exception
        if (hash == null || hash.length == 0) return transactionBuilderSigned.build();

        if (!isMainChain && chainId == null) {
            throw new IllegalArgumentException("chainId required when isMainChain=false");
        }
        byte[] newHash;
        if (isMainChain) {
            newHash = hash;
        } else {
            byte[] hashWithChainId = Arrays.copyOf(hash, hash.length + chainId.length);
            System.arraycopy(chainId, 0, hashWithChainId, hash.length, chainId.length);
            newHash = Sha256Hash.hash(hashWithChainId);
        }

        ECKey.ECDSASignature signature = myKey.sign(newHash);
        ByteString bsSign = ByteString.copyFrom(signature.toByteArray());
        transactionBuilderSigned.addSignature(bsSign);
        transaction = transactionBuilderSigned.build();
        return transaction;
    }

    public static String sign(String unSign, ECKey myKey) {
        if (unSign == null || unSign.isEmpty())
            throw new IllegalArgumentException("unSign must not be empty");
        unSign = stripLeadingHexPrefix(unSign);
        byte[] bytes;
        if (AddressUtil.isHexString(unSign)) {
            bytes = ByteArray.fromHexString(unSign);
        } else {
            bytes = ByteArray.fromString(unSign);
        }
        Sign.SignatureData signatureData = Sign.signPrefixedMessage(bytes, ECKeyPair.create(myKey.getPrivKey()));
        StringBuffer sb = new StringBuffer();
        return sb.append("0x").append(ByteArray.toHexString(signatureData.getR())).append(ByteArray.toHexString(signatureData.getS())).append(ByteArray.toHexString(new byte[]{signatureData.getV()})).toString();
    }


    public static String signMessageV2(byte[] unSign, ECKey myKey) {

        Sign.SignatureData signatureData = Sign.signPrefixedMessageV2(unSign, ECKeyPair.create(myKey.getPrivKey()));
        StringBuffer sb = new StringBuffer();
        return sb.append("0x").append(ByteArray.toHexString(signatureData.getR())).append(ByteArray.toHexString(signatureData.getS())).append(ByteArray.toHexString(new byte[]{signatureData.getV()})).toString();
    }

    public static String signStructuredData(String unsign, ECKey myKey) {
        byte[] bytes = Numeric.hexStringToByteArray(unsign);
        Sign.SignatureData signatureData = Sign.signMessage(bytes, ECKeyPair.create(myKey.getPrivKey()), false);
        StringBuffer sb = new StringBuffer();
        return sb.append("0x").append(ByteArray.toHexString(signatureData.getR())).append(ByteArray.toHexString(signatureData.getS())).append(ByteArray.toHexString(new byte[]{signatureData.getV()})).toString();
    }

    /**
     * TODO used for ledger 4.4.0 add
     * Generate string hash
     *
     * @param unsign
     * @return
     */
    public static byte[] getMessageHash(String unsign) {
        unsign = stripLeadingHexPrefix(unsign);
        byte[] bytes;
        if (AddressUtil.isHexString(unsign)) {
            bytes = ByteArray.fromHexString(unsign);
        } else {
            bytes = ByteArray.fromString(unsign);
        }
        return Sign.getPrefixedMessageHash(bytes);
    }

    /**
     * TODO used for ledger 4.11.2 add
     * Generate string hash
     *
     * @return
     */
    public static byte[] getMessageHashV2(byte[] unSign) {
        return Sign.getPrefixedMessageHashV2(unSign);
    }

    /**
     * TODO used for  ledger 4.4.0 add
     * Signature string result, byte[] converted to String
     *
     * @param signature
     * @return
     */
    public static String enCodeSignature(byte[] signature) {
        if (signature == null || signature.length < 65) {
            throw new IllegalArgumentException("signature must be >= 65 bytes");
        }
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        byte v = signature[64];
        System.arraycopy(signature, 0, r, 0, 32);
        System.arraycopy(signature, 32, s, 0, 32);

        if (v < 27) {
            v += 27;
        }

        Sign.SignatureData signatureData = new Sign.SignatureData(v, r, s);
        StringBuffer sb = new StringBuffer();
        return sb.append("0x").append(ByteArray.toHexString(signatureData.getR())).append(ByteArray.toHexString(signatureData.getS())).append(ByteArray.toHexString(new byte[]{signatureData.getV()})).toString();
    }


    public static Transaction addSignature(Transaction transaction, byte[] signature) {
        if (transaction == null) return transaction;
        Transaction.Builder builder = transaction.toBuilder();
        return builder.addSignature(ByteString.copyFrom(signature)).build();
    }


    /**
     * @param message   unSign
     * @param signature signed
     * @param address   walletAddress
     * @return
     */
    public static boolean verifyMessage(String message, String signature, String address) {

        if (AddressUtil.isEmpty(message, address, signature)) return false;

        try {
            message = stripLeadingHexPrefix(message);
            signature = stripLeadingHexPrefix(signature);
            byte[] signatureBytes;

            if (AddressUtil.isHexString(signature)) {
                signatureBytes = ByteArray.fromHexString(signature);
            } else {
                signatureBytes = ByteArray.fromString(signature);
            }

            if (signatureBytes == null || signatureBytes.length < 65) {
                return false;
            }

            byte[] r = new byte[32];
            byte[] s = new byte[32];
            byte v = signatureBytes[64];
            System.arraycopy(signatureBytes, 0, r, 0, 32);
            System.arraycopy(signatureBytes, 32, s, 0, 32);

            if (v < 27) {
                //revId -> v
                v += 27;
            }
            ECKey.ECDSASignature ecdsaSignature = ECKey.ECDSASignature.fromComponents(r, s, v);
            // use v2
            byte[] bytes = ECKey.signatureToAddress(Sign.getPrefixedMessageHashV2(message.getBytes()), ecdsaSignature);
            if (ArrayUtils.isEmpty(bytes)) return false;

            return Arrays.equals(bytes, AddressUtil.decode58Check(address));
        } catch (Exception e) {
            org.tron.common.utils.LogUtils.e(e);
            return false;
        }
    }

    private static String stripLeadingHexPrefix(String value) {
        return value.startsWith("0x") ? value.substring(2) : value;
    }

    /**
     * @param expiration must be in milliseconds format
     */
    public static Transaction setExpiration(Transaction transaction, long expiration) {
        Transaction.raw rawData = transaction.getRawData().toBuilder().setExpiration(expiration)
                .build();
        return transaction.toBuilder().setRawData(rawData).build();
    }


    public static Transaction setTimestamp(Transaction transaction, long timestamp) {
        Transaction.Builder builder = transaction.toBuilder();
        Transaction.raw.Builder rowBuilder = transaction.getRawData()
                .toBuilder();
        if (timestamp != 0) {
            rowBuilder.setTimestamp(timestamp);
        }
        builder.setRawData(rowBuilder.build());
        return builder.build();
    }

    public static String getOwner(Transaction transaction) throws InvalidProtocolBufferException {
        if (transaction == null || transaction.getRawData() == null || transaction.getRawData().getContractCount() < 1 ||
                getOwner(transaction.getRawData().getContract(0)) == null)
            return "";
        return AddressUtil.encode58Check(getOwner(transaction.getRawData().getContract(0)));
    }


    /**
     * Bandwidth required for the exchange
     *
     * @param transaction transaction
     */
    public static long bandwidthCost(Transaction transaction) {
        return transaction.getSerializedSize() + Parameter.ResConstant.BANDWIDTH_COST + Parameter.ResConstant.SIGNATURE_COST;
    }


    //make sure that contractType is validated before
    //No exception will be thrown here
    public static byte[] getShieldTransactionHashIgnoreTypeException(Transaction tx, String tokenId) {
        try {
            return hashShieldTransaction(tx, tokenId);
        } catch (Exception e) {
            // Swallow per the method name, but log so the failure is diagnosable.
            LogUtils.e(e);
        }
        return null;
    }

    public static byte[] hashShieldTransaction(Transaction tx, String tokenId)
            throws InvalidProtocolBufferException, TronException {
        Any contractParameter = tx.getRawData().getContract(0).getParameter();
        if (!contractParameter.is(ShieldContract.ShieldedTransferContract.class)) {
            throw new TronException(
                    "ContractValidateException:contract type error,expected type [ShieldedTransferContract],real type["
                            + contractParameter
                            .getClass() + "]");
        }

        ShieldContract.ShieldedTransferContract shieldedTransferContract = contractParameter
                .unpack(ShieldContract.ShieldedTransferContract.class);
        ShieldContract.ShieldedTransferContract.Builder newContract = ShieldContract.ShieldedTransferContract.newBuilder();
        newContract.setFromAmount(shieldedTransferContract.getFromAmount());
        newContract.addAllReceiveDescription(shieldedTransferContract.getReceiveDescriptionList());
        newContract.setToAmount(shieldedTransferContract.getToAmount());
        newContract.setTransparentFromAddress(shieldedTransferContract.getTransparentFromAddress());
        newContract.setTransparentToAddress(shieldedTransferContract.getTransparentToAddress());
        for (ShieldContract.SpendDescription spendDescription : shieldedTransferContract.getSpendDescriptionList()) {
            newContract
                    .addSpendDescription(spendDescription.toBuilder().clearSpendAuthoritySignature().build());
        }

        Transaction.raw.Builder rawBuilder = tx.toBuilder()
                .getRawDataBuilder()
                .clearContract()
                .addContract(
                        Contract.newBuilder().setType(Contract.ContractType.ShieldedTransferContract)
                                .setParameter(
                                        Any.pack(newContract.build())).build());

        Transaction transaction = tx.toBuilder().clearRawData()
                .setRawData(rawBuilder).build();
        byte[] mergedByte = Bytes.concat(Sha256Hash.of(tokenId.getBytes()).getBytes(),
                transaction.getRawData().toByteArray());
        return Sha256Hash.of(mergedByte)
                .getBytes();
    }

    public static Transaction addMemo(Transaction transaction, String memo) {
        if (AddressUtil.isEmpty(memo)) return transaction;
        if (transaction == null || transaction.toString().equals("")) return transaction;
        // Memo is encoded as the raw string bytes, matching java-tron's
        // Util.setTransactionExtraData visible=true branch (raw.setData(data.getBytes())); it is
        // read back via Util.getMemo as new String(bytes, UTF-8). The commented hex form below is
        // java-tron's visible=false branch (ByteArray.fromHexString(data)).
//        byte[] memoByte = ByteArray.fromHexString(memo);
        byte[] memoByte = ByteArray.fromString(memo);

        Transaction.Builder builder = transaction.toBuilder();

        Transaction.raw.Builder rawBuilder = transaction.getRawData().toBuilder();

        rawBuilder.setData(ByteString.copyFrom(memoByte));

        return builder.setRawData(rawBuilder.build()).build();

    }

    public static String getTriggerHash(Transaction transaction) {
        if (transaction == null
                || "".equals(transaction.toString())
                || transaction.getRawData() == null
                || transaction.getRawData().getContractCount() < 1) return "";
        Contract contract = transaction.getRawData().getContract(0);
        if (contract.getType() != Contract.ContractType.TriggerSmartContract) return "";
        try {
            SmartContractOuterClass.TriggerSmartContract triggerSmart = unpackContract(contract, SmartContractOuterClass.TriggerSmartContract.class);
            return ByteArray.toHexString(Hash.sha256(triggerSmart.getData().toByteArray()));
        } catch (InvalidProtocolBufferException e) {
            LogUtils.e(e);
        }
        return "";

    }

    /**
     * Create a custom transaction to verify account ownership
     *
     * @param contractName custom contract name
     * @return Transaction
     */
    public static Transaction createCustomContract(String contractName) {
        Transaction.Builder builder = Transaction.newBuilder();
        Transaction.raw.Builder rawBuilder = Transaction.raw.newBuilder();
        Contract.Builder contractBuilder = Contract.newBuilder();
        contractBuilder.setContractName(ByteString.copyFrom(contractName.getBytes()));
        rawBuilder.addContract(contractBuilder.build());
        builder.setRawData(rawBuilder.build());
        return builder.build();
    }

    /**
     * from transaction signed Parse out the signed address
     *
     * @param signedTransaction
     * @return Address
     */
    public static String getTransactionSignatureOwner(Transaction signedTransaction) {
        try {
            byte[] hash = Hash.sha256(signedTransaction.getRawData().toByteArray());
            byte[] address = ECKey
                    .signatureToAddress(hash, TransactionUtils.getBase64FromByteString(signedTransaction.getSignature(0)));
            return AddressUtil.encode58Check(address);
        } catch (Exception e) {
            LogUtils.e(e);

        }
        return "";
    }

    public static boolean checkTransactionEmpty(GrpcAPI.TransactionExtention transactionExtention) {
        if (transactionExtention != null
                && transactionExtention.hasTransaction()
                && transactionExtention.getTransaction() != null
                && transactionExtention.getTransaction().toString().length() > 0
                && transactionExtention.getTransaction().getRawData() != null
        ) {
            return false;
        } else {
            return true;
        }
    }

    public static String getErrorMessage(GrpcAPI.TransactionExtention transactionExtention) {
        if (transactionExtention != null
                && transactionExtention.getResult() != null
                && transactionExtention.getResult().getMessage() != null
                && !transactionExtention.getResult().getMessage().isEmpty()) {
            return new String(transactionExtention.getResult().getMessage().toByteArray());
        }
        return "";
    }


    public static Transaction replaceVoteWitnessContract(Transaction tx, WitnessContract.VoteWitnessContract voteWitnessContract) {
        try {
            Transaction.raw.Builder rawBuilder = tx.toBuilder()
                    .getRawDataBuilder()
                    .clearContract()
                    .addContract(Contract.newBuilder().setType(Contract.ContractType.VoteWitnessContract)
                            .setParameter(
                                    Any.pack(voteWitnessContract)));
            Transaction transaction = tx.toBuilder().clearRawData()
                    .setRawData(rawBuilder).build();

            return transaction;
        } catch (Exception e) {
            LogUtils.e(e);
        }
        return null;
    }

}
