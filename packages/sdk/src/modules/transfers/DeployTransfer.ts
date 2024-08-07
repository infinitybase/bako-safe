import { BaseTransfer, BaseTransferLike } from './BaseTransfer';
import {
  Address,
  bn,
  calculateGasFee,
  ContractUtils,
  CreateTransactionRequest,
  OutputType,
  Provider,
  ScriptTransactionRequest,
  TransactionCreate,
  transactionRequestify,
  ZeroBytes32,
} from 'fuels';
import {
  IBakoSafeAuth,
  ITransaction,
  TransactionService,
  TransactionStatus,
} from '../../api';

import { Vault } from '../vault';

import { FAKE_WITNESSES } from './fee';

/* Types */
type BaseDeployTransfer = BaseTransferLike<CreateTransactionRequest>;
type DeployTransferFromTransaction = TransactionCreate &
  Omit<
    BaseDeployTransfer,
    | 'transactionRequest'
    | 'witnesses'
    | 'service'
    | 'BakoSafeTransaction'
    | 'BakoSafeTransactionId'
  > & { auth?: IBakoSafeAuth };
type DeployTransferTransactionRequest = TransactionCreate &
  Pick<BaseDeployTransfer, 'vault'>;
type DeployBakoTransaction = {
  auth: IBakoSafeAuth;
  vault: DeployTransferFromTransaction['vault'];
} & ITransaction;

const { getContractId, getContractStorageRoot } = ContractUtils;

/* TODO: Move this method to vault */
const getMaxPredicateGasUsed = async (provider: Provider, signers: number) => {
  const request = new ScriptTransactionRequest();
  const addresses = Array.from({ length: signers }, () => Address.fromRandom());
  const vault = await Vault.create({
    configurable: {
      SIGNATURES_COUNT: signers,
      SIGNERS: addresses.map((address) => address.toB256()),
      network: provider.url,
    },
  });

  // Add fake input
  request.addCoinInput({
    id: ZeroBytes32,
    assetId: ZeroBytes32,
    amount: bn(),
    owner: vault.address,
    blockCreated: bn(),
    txCreatedIdx: bn(),
  });

  // Populate the  transaction inputs with predicate data
  vault.populateTransactionPredicateData(request);
  Array.from({ length: signers }, () => request.addWitness(FAKE_WITNESSES));

  const transactionCost = await vault.provider.getTransactionCost(request);
  await vault.fund(request, transactionCost);
  await vault.provider.estimatePredicates(request);
  const input = request.inputs[0];
  if ('predicate' in input && input.predicate) {
    return bn(input.predicateGasUsed);
  }

  return bn();
};

/**
 * `DeployTransfer` are extension of CreateTransactionRequest, to create and deploy contracts
 */
export class DeployTransfer extends BaseTransfer<CreateTransactionRequest> {
  /**
   * Static method to create a new instance of DeployTransfer from a BakoTransaction.
   *
   * @param {DeployBakoTransaction} options - The parameters for creating a DeployTransfer.
   * @returns {DeployTransfer} A new instance of DeployTransfer.
   */
  static async fromBakoTransaction(options: DeployBakoTransaction) {
    const { auth, vault, ...bakoTransaction } = options;
    const createTransactionRequest = CreateTransactionRequest.from(
      bakoTransaction.txData,
    );

    const witnesses = [
      bakoTransaction.txData.witnesses[
        createTransactionRequest.bytecodeWitnessIndex ?? 0
      ].toString(),
      ...bakoTransaction.resume.witnesses.map((witness) => witness.signature),
    ];

    return new DeployTransfer({
      vault,
      name: bakoTransaction.name,
      witnesses,
      service: new TransactionService(auth),
      transactionRequest: createTransactionRequest,
      BakoSafeTransaction: bakoTransaction,
      BakoSafeTransactionId: bakoTransaction.id,
    });
  }

  /**
   * Static method to create a new instance of DeployTransfer from a TransactionCreate.
   *
   * @param {DeployTransferFromTransaction} options - The parameters for creating a DeployTransfer.
   * @returns {Promise<DeployTransfer>} A new instance of DeployTransfer.
   */
  static async fromTransactionCreate(
    options: DeployTransferFromTransaction,
  ): Promise<DeployTransfer> {
    const { name, vault, witnesses, auth, ...transaction } = options;
    const transactionRequest = await this.createTransactionRequest({
      witnesses,
      vault,
      ...transaction,
    });
    const deployTransfer = new DeployTransfer({
      name,
      vault,
      transactionRequest,
      witnesses: witnesses.map((witness) => witness.data),
    });

    if (auth) {
      deployTransfer.service = new TransactionService(auth);
    }

    return deployTransfer;
  }

  /**
   * Static method to create a TransactionRequest for a DeployTransfer.
   * @param {DeployTransferTransactionRequest} options - The parameters for creating a TransactionRequest.
   * @param {Vault} options.vault - The vault associated with the transfer.
   * @param {Input[]} options.inputs - The inputs for the transfer.
   * @param {Witness[]} options.witnesses - The witnesses for the transfer.
   * @param {TransactionCreate} options.transaction - The transaction to be used for the transfer.
   * @returns {Promise<CreateTransactionRequest>} A new instance of CreateTransactionRequest.
   */
  static async createTransactionRequest(
    options: DeployTransferTransactionRequest,
  ): Promise<CreateTransactionRequest> {
    const { vault, inputs, witnesses, ...transaction } = options;

    const bytecode = witnesses[transaction.bytecodeWitnessIndex];
    const contractOutput = transaction.outputs.find(
      (output) => output.type === OutputType.ContractCreated,
    );

    if (!contractOutput || !bytecode) {
      throw new Error('Contract output and bytecode are required.');
    }

    let transactionRequest = CreateTransactionRequest.from({
      inputs: [],
      salt: transaction.salt,
      witnesses: [bytecode.data],
      storageSlots: transaction.storageSlots,
      outputs: [contractOutput],
      bytecodeWitnessIndex: transaction.bytecodeWitnessIndex,
    });

    // Get the transaction cost and set max fee to fund the transaction with required inputs
    const transactionCost =
      await vault.provider.getTransactionCost(transactionRequest);
    transactionRequest.maxFee = transactionCost.maxFee;
    transactionRequest = await vault.fund(transactionRequest, transactionCost);

    // Estimate the gas usage for the predicate
    const predicateGasUsed = await getMaxPredicateGasUsed(
      vault.provider,
      vault.BakoSafeVault.minSigners,
    );

    // Calculate the total gas usage for the transaction
    let totalGasUsed = bn(0);
    transactionRequest.inputs.forEach((input) => {
      if ('predicate' in input && input.predicate) {
        totalGasUsed = totalGasUsed.add(predicateGasUsed);
      }
    });

    // Estimate the max fee for the transaction and calculate fee difference
    const { gasPriceFactor } = await vault.provider.getGasConfig();
    const { maxFee, gasPrice } = await vault.provider.estimateTxGasAndFee({
      transactionRequest,
    });

    const predicateSuccessFeeDiff = calculateGasFee({
      gas: totalGasUsed,
      priceFactor: gasPriceFactor,
      gasPrice,
    });

    const feeWithFat = maxFee.add(predicateSuccessFeeDiff);
    transactionRequest.maxFee = feeWithFat;

    // Attach missing inputs (including estimated predicate gas usage) / outputs to the request
    await vault.provider.estimateTxDependencies(transactionRequest);

    return transactionRequest;
  }

  /**
   * Store the current transaction in server.
   *
   * @throws {Error} If the transaction has already been saved or if the service is not available.
   * @returns {Promise<DeployTransfer>} The current instance of DeployTransfer.
   */
  async save() {
    if (this.BakoSafeTransactionId || this.BakoSafeTransaction) {
      throw new Error('Transaction already saved.');
    }

    if (!this.service) {
      throw new Error('Auth is required to save the transaction.');
    }

    const transactionData = await this.service.create({
      assets: [],
      hash: this.getHashTxId(),
      txData: transactionRequestify(this.transactionRequest),
      status: TransactionStatus.AWAIT_REQUIREMENTS,
      predicateAddress: this.vault.address.toString(),
      name: this.name,
    });

    this.BakoSafeTransaction = transactionData;
    this.BakoSafeTransactionId = transactionData.id;

    return this;
  }

  /**
   * Gets the contract ID for the current transaction request.
   * This method first converts the transaction request to a transaction.
   * It then retrieves the bytecode from the transaction's witnesses.
   * Finally, it calls the getContractId function with the bytecode, the transaction's salt, and the storage root of the transaction's storage slots.
   * @returns {string} The contract ID.
   */
  getContractId(): string {
    const transaction = this.transactionRequest.toTransaction();
    const bytecode =
      transaction.witnesses[transaction.bytecodeWitnessIndex].data;

    return getContractId(
      bytecode,
      transaction.salt,
      getContractStorageRoot(transaction.storageSlots),
    );
  }
}
