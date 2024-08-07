import { BN, WalletUnlocked, bn } from 'fuels';
import { BakoSafe } from '../../configurables';
import { Vault } from '../../src/modules/vault/Vault';

export const txParams = {
  maxFee: bn(BakoSafe.getGasConfig('MAX_FEE')),
  gasLimit: bn(BakoSafe.getGasConfig('GAS_LIMIT')),
};

export const sendPredicateCoins = async (
  predicate: Vault,
  amount: BN,
  asset: string,
  rootWallet: WalletUnlocked,
) => {
  const deposit = await rootWallet.transfer(
    predicate.address.toString(),
    amount,
    asset,
    txParams,
  );

  return await deposit.waitForResult();
};
