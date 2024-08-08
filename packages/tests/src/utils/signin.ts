import { Wallet, Address, BigNumberCoder, concat } from 'fuels';
import { IBakoSafeAuth, TransactionService } from 'bakosafe';

import { accounts } from '../mocks';
import { LocalProvider } from './provider';

export const signin = async (
  tx_hash: string,
  account: 'FULL' | 'USER_1' | 'USER_2' | 'USER_3' | 'USER_4' | 'USER_5',
  auth?: IBakoSafeAuth,
  BakoSafeTransactionId?: string,
) => {
  const fuelProvider = new LocalProvider();

  const signer = Wallet.fromPrivateKey(
    accounts[account].privateKey,
    fuelProvider,
  );
  const tx = await signer.signMessage(tx_hash);
  // console.log('[ASSINATURAS]', {
  //   normal: tx,
  //   prefix: concat([new BigNumberCoder(`u64`).encode(1), tx]),
  //   //bite: new BigNumberCoder(`u64`).encode(2).toString(),
  // });

  // if (!!auth && BakoSafeTransactionId) {
  //   const acc = Address.fromString(accounts[account].address).toString();
  //   const serviceTransactions = new TransactionService(auth);
  //   return await serviceTransactions.sign(BakoSafeTransactionId, acc, tx);
  // }

  //return [tx, concat([new BigNumberCoder(`u64`).encode(1), tx])];
  return tx;
};
