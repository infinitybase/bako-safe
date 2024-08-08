import {
  BN,
  bn,
  BytesLike,
  ContractFactory,
  DeployContractOptions,
  JsonAbi,
  Predicate,
  Provider,
} from 'fuels';
import { join } from 'path';
import { readFileSync } from 'fs';
import { ContractAbi__factory } from '../../types/sway';

export class BakoContractDeploy extends ContractFactory {
  readonly abi: JsonAbi;
  readonly predicate: string;

  constructor(
    bytecode: BytesLike,
    abi: JsonAbi,
    provider: Provider,
    predicate: string,
  ) {
    super(bytecode, abi, provider);
    this.predicate = predicate;
    this.abi = abi;
  }

  async deploy(deployContractOptions: DeployContractOptions = {}) {
    if (!this.predicate) {
      throw new Error('Predicate not set');
    }

    const { configurableConstants } = deployContractOptions;

    if (configurableConstants) {
      this.setConfigurableConstants(configurableConstants);
    }

    const { contractId, transactionRequest } = this.createTransactionRequest(
      deployContractOptions,
    );

    return {
      contractId,
      transactionRequest,
    };
  }
}

export const createTransactionDeploy = async (
  provider: Provider,
  vault: Predicate<any>,
  maxFee?: BN | number,
) => {
  const byteCodePath = join(
    __dirname,
    `../../sway/contract/out/debug/contract.bin`,
  );

  const byteCode = readFileSync(byteCodePath);

  const deploy_class = new BakoContractDeploy(
    byteCode,
    ContractAbi__factory.abi,
    provider,
    vault.address.toB256(),
  );

  const { transactionRequest, contractId } = await deploy_class.deploy();

  const coins = await vault.getResourcesToSpend([
    {
      amount: bn(1),
      assetId: provider.getBaseAssetId(),
    },
  ]);
  transactionRequest.addResources(coins);

  return {
    transactionRequest,
    contractId,
  };
};
