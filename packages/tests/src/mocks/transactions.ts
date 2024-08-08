import { Provider } from 'fuels';
import { IFormatTransfer } from 'bakosafe';
import {
  assets,
  DEFAULT_BALANCES,
  DEFAULT_MULTI_ASSET_BALANCES,
} from './assets';
import { v4 as uuidv4 } from 'uuid';

export const DEFAULT_TRANSACTION_PAYLOAD = (
  address: string,
  provider?: Provider,
): IFormatTransfer => {
  return {
    name: `tx_${uuidv4()}`,
    assets: DEFAULT_BALANCES.map((balance) => ({
      assetId: !!provider ? provider.getBaseAssetId() : assets['ETH'],
      amount: balance.amount.format(),
      to: address,
    })),
  };
};

export const DEFAULT_MULTI_ASSET_TRANSACTION_PAYLOAD = (
  address: string,
  assetIds?: string[],
): IFormatTransfer => {
  return {
    name: `tx_${uuidv4()}`,
    assets: DEFAULT_MULTI_ASSET_BALANCES.filter(
      (balance) => !assetIds || assetIds.includes(balance.assetId),
    ).map((balance) => ({
      assetId: balance.assetId,
      amount: balance.amount.format(),
      to: address,
    })),
  };
};
