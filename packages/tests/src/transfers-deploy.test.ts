import {
  bn,
  Wallet,
  Provider,
  ContractUtils,
  CreateTransactionRequest,
} from 'fuels';
import { callContractMethod, createTransactionDeploy } from './utils';

import { accounts } from './mocks';
import { BakoSafe } from 'bakosafe';
import { DeployTransfer, TransactionStatus, Vault } from 'bakosafe';
import { authService, IUserAuth, newVault, signin } from './utils';

/* Test util to get id from transaction request */
const getContractId = (request: CreateTransactionRequest) => {
  const createTransaction = request.toTransaction();
  const contractBytecode =
    createTransaction.witnesses[createTransaction.bytecodeWitnessIndex];
  return ContractUtils.getContractId(
    contractBytecode.data,
    request.salt,
    ContractUtils.getContractStorageRoot(createTransaction.storageSlots),
  );
};

describe('[TRANSFERS] Deploy', () => {
  let auth: IUserAuth;
  let provider: Provider;
  let signers: string[];

  // Set providers
  BakoSafe.setProviders({
    CHAIN_URL: 'http://localhost:4000/v1/graphql',
    SERVER_URL: 'http://localhost:3333',
    CLIENT_URL: 'http://localhost:5174',
  });

  beforeAll(async () => {
    provider = await Provider.create(BakoSafe.getProviders('CHAIN_URL'));
    auth = await authService(
      ['FULL', 'USER_1', 'USER_2', 'USER_3', 'USER_5', 'USER_4'],
      provider.url,
    );

    signers = [
      accounts['FULL'].address,
      accounts['USER_1'].address,
      accounts['USER_3'].address,
      accounts['USER_4'].address,
    ];
  }, 30 * 1000);

  test('Create a transaction request for deploy', async () => {
    const vault = await newVault(
      signers,
      provider,
      auth['USER_1'].BakoSafeAuth,
      100,
      1,
    );

    const { transactionRequest, contractId: expectedContractId } =
      await createTransactionDeploy(
        provider,
        vault,
        BakoSafe.getGasConfig('MAX_FEE'),
      );
    const request = await DeployTransfer.createTransactionRequest({
      ...transactionRequest.toTransaction(),
      vault,
    });

    const contractId = getContractId(request);

    expect(expectedContractId).toEqual(contractId);
  });

  test(
    'Create a DeployTransfer instance from transaction create',
    async () => {
      const vault = await newVault(
        signers,
        provider,
        auth['USER_1'].BakoSafeAuth,
        100,
      );

      const { transactionRequest, contractId: expectedContractId } =
        await createTransactionDeploy(
          provider,
          vault,
          BakoSafe.getGasConfig('MAX_FEE'),
        );
      const deployTransfer = await DeployTransfer.fromTransactionCreate({
        ...transactionRequest.toTransaction(),
        vault,
        name: 'Contract deploy',
      });

      const contractIdFromRequest = getContractId(transactionRequest);
      const contractIdFromTransfer = deployTransfer.getContractId();

      expect(contractIdFromTransfer).toBe(contractIdFromRequest);
      expect(expectedContractId).toEqual(contractIdFromRequest);
    },
    100 * 1000,
  );

  test(
    'Submit a DeployTransfer and execute contract',
    async () => {
      const { USER_1: user } = auth;
      const { FULL: genesis } = accounts;

      const vault = await newVault(
        signers,
        provider,
        user.BakoSafeAuth,
        10000,
        1,
      );
      const { transactionRequest, contractId } = await createTransactionDeploy(
        provider,
        vault,
        BakoSafe.getGasConfig('MAX_FEE'),
      );

      const transaction = transactionRequest.toTransaction();
      const deployTransfer = await vault.BakoSafeDeployContract({
        ...transaction,
        name: '[TEST] Contract deploy',
      });

      await signin(
        deployTransfer.getHashTxId(),
        'USER_1',
        user.BakoSafeAuth,
        deployTransfer.BakoSafeTransactionId,
      );

      await deployTransfer.wait();
      expect(contractId).toBe(deployTransfer.getContractId());

      const { value } = await callContractMethod({
        method: 'zero',
        contractId: contractId,
        account: Wallet.fromPrivateKey(genesis.privateKey, provider),
      });

      expect(Number(value)).toBe(0);
    },
    100 * 1000,
  );

  test(
    'Submit a DeployTransfer by vault',
    async () => {
      const { USER_1: user } = auth;

      const vault = await newVault(
        signers,
        provider,
        user.BakoSafeAuth,
        10000,
        2,
      );
      const { transactionRequest, contractId } = await createTransactionDeploy(
        provider,
        vault,
        BakoSafe.getGasConfig('MAX_FEE'),
      );

      const transaction = transactionRequest.toTransaction();
      const deployTransfer = await vault.BakoSafeDeployContract({
        ...transaction,
        name: '[TEST] Contract deploy',
      });

      expect(deployTransfer.getContractId()).toBe(contractId);
    },
    100 * 1000,
  );

  test('Create deploy transfer and get the transaction by id', async () => {
    const { USER_1: user, FULL: genesisAccount } = await authService(
      ['USER_1', 'FULL'],
      provider.url,
    );

    // Create a new vault
    const vault = await newVault(
      signers,
      provider,
      user.BakoSafeAuth,
      10000,
      1,
    );

    // Send coins to the vault
    const wallet = Wallet.fromPrivateKey(genesisAccount.privateKey!, provider);
    await wallet.transfer(vault.address, bn.parseUnits('0.1'));

    // Create the transaction request
    let { transactionRequest } = await createTransactionDeploy(
      provider,
      vault,
      BakoSafe.getGasConfig('MAX_FEE'),
    );

    const transaction = transactionRequest.toTransaction();
    const deployTransfer = await vault.BakoSafeDeployContract({
      ...transaction,
      name: '[TEST] Contract deploy',
    });

    await signin(
      deployTransfer.getHashTxId(),
      'USER_1',
      user.BakoSafeAuth,
      deployTransfer.BakoSafeTransactionId,
    );
    const apiDeployTransfer = await vault.BakoSafeGetTransaction(
      deployTransfer.BakoSafeTransactionId,
    );
    const resume = await apiDeployTransfer.wait();

    expect(deployTransfer.BakoSafeTransactionId).toBe(
      apiDeployTransfer.BakoSafeTransactionId,
    );
    expect(apiDeployTransfer).toBeInstanceOf(DeployTransfer);
    expect(resume.status).toBe(TransactionStatus.SUCCESS);
  });
});
