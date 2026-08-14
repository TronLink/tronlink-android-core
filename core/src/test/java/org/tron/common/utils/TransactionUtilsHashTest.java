package org.tron.common.utils;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.tron.common.crypto.ECKey;
import org.tron.protos.Protocol;
import org.tron.protos.contract.BalanceContract;
import org.tron.protos.contract.SmartContractOuterClass;

public class TransactionUtilsHashTest {

    @Test
    public void transactionHash_matchesRawDataSha256() {
        Protocol.Transaction transaction = createTransferTransaction();

        String expected = Hex.toHexString(
                Sha256Hash.hash(transaction.getRawData().toByteArray()));

        Assert.assertEquals(expected, TransactionUtils.getHash(transaction));
        Assert.assertEquals(expected, TransactionUtils.getTransactionHash(transaction));
    }

    @Test
    public void transactionHash_changesOnlyWhenRawDataChanges() {
        Protocol.Transaction transaction = createTransferTransaction();
        String originalHash = TransactionUtils.getTransactionHash(transaction);

        Protocol.Transaction signed = TransactionUtils.sign(transaction, new ECKey());
        Assert.assertEquals(originalHash, TransactionUtils.getTransactionHash(signed));

        Protocol.Transaction timestamped = TransactionUtils.setTimestamp(transaction, 123456789L);
        Assert.assertNotEquals(originalHash, TransactionUtils.getTransactionHash(timestamped));
    }

    @Test
    public void getBase64FromByteString_returnsEmptyForMalformedSignature() {
        Assert.assertEquals("", TransactionUtils.getBase64FromByteString(ByteString.copyFrom(new byte[64])));
    }

    @Test
    public void getBase64FromByteString_returnsEmptyForNullSignature() {
        Assert.assertEquals("", TransactionUtils.getBase64FromByteString(null));
    }

    @Test
    public void getOwner_supportsUpdateSettingContract() {
        ByteString owner = ByteString.copyFrom(Hex.decode("41a0abd659056697b68feeed0d4bcab3752c01a0f9"));
        SmartContractOuterClass.UpdateSettingContract updateSetting =
                SmartContractOuterClass.UpdateSettingContract.newBuilder()
                        .setOwnerAddress(owner)
                        .build();
        Protocol.Transaction.Contract contract = Protocol.Transaction.Contract.newBuilder()
                .setType(Protocol.Transaction.Contract.ContractType.UpdateSettingContract)
                .setParameter(Any.pack(updateSetting))
                .build();

        Assert.assertArrayEquals(owner.toByteArray(), TransactionUtils.getOwner(contract));
    }

    private static Protocol.Transaction createTransferTransaction() {
        byte[] owner = Hex.decode("41a0abd659056697b68feeed0d4bcab3752c01a0f9");
        byte[] to = Hex.decode("41b0abd659056697b68feeed0d4bcab3752c01a0fa");

        BalanceContract.TransferContract transfer = BalanceContract.TransferContract.newBuilder()
                .setOwnerAddress(ByteString.copyFrom(owner))
                .setToAddress(ByteString.copyFrom(to))
                .setAmount(1000000L)
                .build();

        Protocol.Transaction.Contract contract = Protocol.Transaction.Contract.newBuilder()
                .setType(Protocol.Transaction.Contract.ContractType.TransferContract)
                .setParameter(Any.pack(transfer))
                .build();

        Protocol.Transaction.raw raw = Protocol.Transaction.raw.newBuilder()
                .setRefBlockBytes(ByteString.copyFrom(Hex.decode("0001")))
                .setRefBlockHash(ByteString.copyFrom(Hex.decode("1122334455667788")))
                .setExpiration(1710000000000L)
                .setTimestamp(1709999940000L)
                .addContract(contract)
                .build();

        return Protocol.Transaction.newBuilder()
                .setRawData(raw)
                .build();
    }
}
