import { ContractAbi, ContractAbi__factory } from '../../types/sway';
import { Account } from 'fuels';

export type ContractInstanceParams = { contractId: string; account: Account };
export type CallContractParams = ContractInstanceParams & {
  method: keyof ContractAbi['functions'];
};

export const getContractInstance = async (params: ContractInstanceParams) =>
  ContractAbi__factory.connect(params.contractId, params.account);

export const callContractMethod = async (params: CallContractParams) => {
  const contract = await getContractInstance(params);
  return (await contract.functions[params.method]().call()).waitForResult();
};
