package org.tron;

import com.google.protobuf.ByteString;

import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.tron.api.GrpcAPI;
import org.tron.api.WalletGrpc;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.ByteUtil;
import org.tron.common.utils.TransactionDataUtils;
import org.tron.common.utils.TransactionUtils;
import org.tron.common.utils.abi.AbiUtil;
import org.tron.config.Parameter;
import org.tron.net.input.TriggerContractRequest;
import org.tron.protos.Protocol;
import org.tron.protos.contract.AssetIssueContractOuterClass;
import org.tron.protos.contract.BalanceContract;
import org.tron.protos.contract.SmartContractOuterClass;
import org.tron.walletserver.AddressUtil;
import org.tron.walletserver.I_TYPE;
import org.tron.walletserver.Wallet;

import java.util.concurrent.TimeUnit;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

public class TransactionCoreUnitTest {
    public static final String TAG_TRANSACTION = "transaction";
    public static final String TAG_ADDRESS = "Address";
    String tgtIp = "grpc.trongrid.io:50051";

    private static final String WALLET_NAME = "walletTest";
    private static final String PRIVATE_KEY = "";
    private static final String WALLET_ADDRESS = "";
    private static final String WALLET_ADDRESS_TO = "";
    private static final String TOKEN_ID = "1004114";//you can use your any test tokenid of any trc10 token
    private static final String CONTRACT_ADDRESS = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";//you can use your any test contract address of any trc20 token

    private static final long AMOUNT = 1000000l;


    Wallet testWallet = null;
    private ManagedChannel channel = null;
    private WalletGrpc.WalletBlockingStub stub;

    @Test
    public void importWalletWithPrivateKey() throws Exception {
        if ("".equals(PRIVATE_KEY)) {
            throw new Exception("You must assign values to the parameter called PRIVATE_KEY to make sure you can run");
        }
        testWallet = new Wallet(I_TYPE.PRIVATE, PRIVATE_KEY);
        testWallet.setWalletName(WALLET_NAME);
        testWallet.setCreateType(Parameter.CreateWalletType.TYPE_IMPORT_PRIKEY);
        testWallet.setCreateTime(System.currentTimeMillis());
        System.out.println(TAG_ADDRESS + " = " + testWallet.getAddress());
    }

    @Test
    public void connectNode() throws Exception {
        importWalletWithPrivateKey();
        channel = ManagedChannelBuilder.forTarget(tgtIp)
                .usePlaintext()
                .build();
        stub = WalletGrpc.newBlockingStub(channel);
        if ("".equals(WALLET_ADDRESS)) {
            throw new Exception("You must assign values to the parameter called " +
                    "WALLET_ADDRESS to make sure you can run");
        }
        ByteString addressBS = ByteString.copyFrom(AddressUtil.decode58Check(WALLET_ADDRESS));
        Protocol.Account request = Protocol.Account.newBuilder().setAddress(addressBS).build();
        Protocol.Account account = stub.withDeadlineAfter(10, TimeUnit.SECONDS).getAccount(request);
        Assert.assertNotNull(account);
        System.out.println(account.getBalance());
        //if wallet is Activated use the code below
        //assertEquals(WALLET_ADDRESS, AddressUtil.encode58Check(account.getAddress().toByteArray()));
    }

    @Test
    public void trxTransactionTransactionTest() throws Exception {
        initBlockStub();
        Protocol.Transaction transaction = createTrxTransferTransaction(WALLET_ADDRESS, WALLET_ADDRESS_TO, AMOUNT);
        Assert.assertNotNull(transaction);
    }

    @Test
    public void trc20TransactionTransactionTest() throws Exception {
        initBlockStub();
        Protocol.Transaction transaction = createTrc20TransferTransaction(WALLET_ADDRESS, WALLET_ADDRESS_TO, CONTRACT_ADDRESS);
        Assert.assertNotNull(transaction);
    }

    @Test
    public void trc10TransctionTransactionTest() throws Exception {
        initBlockStub();
        Protocol.Transaction transaction = createTrc10TransferTransaction(WALLET_ADDRESS, WALLET_ADDRESS_TO, TOKEN_ID, AMOUNT);
        Assert.assertNotNull(transaction);
    }

    @Test
    public void signTest() throws Exception {
        importWalletWithPrivateKey();
        initBlockStub();
        Protocol.Transaction transactionSigned = sign(createTrxTransferTransaction(WALLET_ADDRESS, WALLET_ADDRESS_TO, AMOUNT));
        Assert.assertNotNull(transactionSigned);
    }

    @Test
    public void broadcastTransactionTest() throws Exception {
        boolean sent;
        importWalletWithPrivateKey();
        initBlockStub();
        Protocol.Transaction transactionSigned = sign(createTrxTransferTransaction(WALLET_ADDRESS, WALLET_ADDRESS_TO, AMOUNT));
        sent = broadcastTransaction(transactionSigned);
        Assert.assertTrue(sent);
    }

    private Protocol.Transaction sign(Protocol.Transaction transaction) {
        //sign
        Protocol.Transaction mTransactionSigned = TransactionUtils.sign(transaction, testWallet.getECKey());
        System.out.println(TAG_TRANSACTION + " = " + mTransactionSigned.toString());
        return mTransactionSigned;
    }

    public boolean broadcastTransaction(Protocol.Transaction mTransactionSigned) {
        GrpcAPI.Return aReturn = stub.broadcastTransaction(mTransactionSigned);
        return aReturn != null && aReturn.getResult();
    }


    public void initBlockStub() {
        channel = ManagedChannelBuilder.forTarget(tgtIp)
                .usePlaintext()
                .build();
        stub = WalletGrpc.newBlockingStub(channel);
    }

    @After
    public void tearDown() {
        if (channel != null) {
            channel.shutdown();
            channel = null;
        }
    }

    public Protocol.Transaction createTrxTransferTransaction(String ownerAddress, String toAddress, long amount) throws Exception {
        if ("".equals(ownerAddress) || "".equals(toAddress)) {
            throw new Exception("You must assign values to the parameters called " +
                    "WALLET_ADDRESS , WALLET_ADDRESS_TO and CONTRACT_ADDRESS, to make sure you can run");
        }
        channel = ManagedChannelBuilder.forTarget(tgtIp)
                .usePlaintext()
                .build();
        stub = WalletGrpc.newBlockingStub(channel);
        byte[] owner = AddressUtil.decode58Check(ownerAddress);
        byte[] to = AddressUtil.decode58Check(toAddress);
        // trx
        BalanceContract.TransferContract.Builder builder = BalanceContract.TransferContract.newBuilder();
        ByteString bsTo = ByteString.copyFrom(to);
        ByteString bsOwner = ByteString.copyFrom(owner);
        builder.setToAddress(bsTo);
        builder.setOwnerAddress(bsOwner);
        builder.setAmount(amount);
        BalanceContract.TransferContract transferContract = builder.build();
        Protocol.Transaction transaction = null;
        GrpcAPI.TransactionExtention transactionExtentionTRX = stub.
                withDeadlineAfter(8, TimeUnit.SECONDS).createTransaction2(transferContract);
        if (transactionExtentionTRX.hasResult() && transactionExtentionTRX.getTransaction().toString().length() > 0) {
            transaction = transactionExtentionTRX.getTransaction();
        }
        // Fail with an assertion instead of an NPE when the node returns no result.
        Assert.assertNotNull("createTransaction2 returned no transaction", transaction);
        System.out.println(TAG_TRANSACTION + " = " + transaction.toString());
        return transaction;
    }

    public Protocol.Transaction createTrc10TransferTransaction(String ownerAddress, String toAddress, String tokenIdStr, long amount) throws Exception {
        if ("".equals(ownerAddress) || "".equals(toAddress) || "".equals(tokenIdStr)) {
            throw new Exception("You must assign values to the parameters called " +
                    "WALLET_ADDRESS , WALLET_ADDRESS_TO and TOKEN_ID, to make sure you can run");
        }
        channel = ManagedChannelBuilder.forTarget(tgtIp)
                .usePlaintext()
                .build();
        stub = WalletGrpc.newBlockingStub(channel);
        byte[] owner = AddressUtil.decode58Check(ownerAddress);
        byte[] to = AddressUtil.decode58Check(toAddress);
        byte[] tokenId = tokenIdStr.getBytes();
        Protocol.Transaction transaction = null;
        GrpcAPI.TransactionExtention transferExtention = null;
        AssetIssueContractOuterClass.TransferAssetContract contract = null;

        AssetIssueContractOuterClass.TransferAssetContract.Builder transferAssetContractBuilder =
                AssetIssueContractOuterClass.TransferAssetContract.newBuilder();
        ByteString bsTo = ByteString.copyFrom(to);
        ByteString bsName = ByteString.copyFrom(tokenId);
        ByteString bsOwner = ByteString.copyFrom(owner);
        transferAssetContractBuilder.setToAddress(bsTo);
        transferAssetContractBuilder.setAssetName(bsName);
        transferAssetContractBuilder.setOwnerAddress(bsOwner);
        transferAssetContractBuilder.setAmount(amount);
        contract = transferAssetContractBuilder.build();
        transferExtention = stub.transferAsset2(contract);
        if (transferExtention.hasResult() && transferExtention.getTransaction().toString().length() > 0) {
            transaction = transferExtention.getTransaction();
        }
        // Fail with an assertion instead of an NPE when the node returns no result.
        Assert.assertNotNull("transferAsset2 returned no transaction", transaction);
        System.out.println(TAG_TRANSACTION + " = " + transaction.toString());
        return transaction;

    }

    public Protocol.Transaction createTrc20TransferTransaction(String ownerAddress, String toAddress, String contractAddress) throws Exception {
        if ("".equals(ownerAddress) || "".equals(toAddress) || "".equals(contractAddress)) {
            throw new Exception("You must assign values to the parameters called " +
                    "WALLET_ADDRESS , WALLET_ADDRESS_TO and CONTRACT_ADDRESS, to make sure you can run");
        }
        //trx20
        TriggerContractRequest triggerContractRequest = new TriggerContractRequest();
        String methodStr = TransactionDataUtils.transferMethod;
        GrpcAPI.TransactionExtention transactionExtention = null;
        triggerContractRequest.setMethodStr(methodStr);
        triggerContractRequest.setArgsStr(toAddress + "," + AMOUNT);
        triggerContractRequest.setFeeLimit(Parameter.ResConstant.feeLimit);
        triggerContractRequest.setContractAddrStr(contractAddress);
        triggerContractRequest.setHex(false);
        triggerContractRequest.setTokenCallValue(0);
        triggerContractRequest.setOwer(AddressUtil.decodeFromBase58Check(ownerAddress));


        //get TransactionExtention

        String contractAddrStr = triggerContractRequest.getContractAddrStr();
        String methodString = triggerContractRequest.getMethodStr();
        String argsStr = triggerContractRequest.getArgsStr();
        byte[] ower = triggerContractRequest.getOwer();
        boolean isHex = triggerContractRequest.isHex();
        long feeLimit = triggerContractRequest.getFeeLimit();
        long callValue = triggerContractRequest.getCallValue();
        long tokenCallValue = triggerContractRequest.getTokenCallValue();


        byte[] inputBytes;
        if (triggerContractRequest.isAbiPro()) {
            String methodId = triggerContractRequest.getMethodABI();
            String encode = ByteArray.toHexString(AbiUtil.encodeInput(triggerContractRequest.getMethodStr(), triggerContractRequest.getArgsStr()));
            inputBytes = ByteArray.fromHexString(methodId + encode);
        } else {
            inputBytes = Hex.decode(AbiUtil.parseMethod(methodStr, argsStr, isHex));
        }

        byte[] contractAddressBytes = AddressUtil.decodeFromBase58Check(contractAddrStr);


        SmartContractOuterClass.TriggerSmartContract.Builder triggerContractBuild

                = SmartContractOuterClass.TriggerSmartContract.newBuilder();
        if (!ByteUtil.isNullOrZeroArray(ower))
            triggerContractBuild.setOwnerAddress(ByteString.copyFrom(ower));
        if (!ByteUtil.isNullOrZeroArray(contractAddressBytes))
            triggerContractBuild.setContractAddress(ByteString.copyFrom(contractAddressBytes));
        if (!ByteUtil.isNullOrZeroArray(inputBytes))
            triggerContractBuild.setData(ByteString.copyFrom(inputBytes));
        triggerContractBuild.setCallValue(callValue);


        transactionExtention = stub.triggerConstantContract(triggerContractBuild.build());

        Protocol.Transaction transaction = transactionExtention.getTransaction();
        System.out.println(TAG_TRANSACTION + " = " + transaction.toString());
        return transaction;
    }

}
