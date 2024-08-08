import { BakoSafe } from 'bakosafe';
import { IBakoSafeAuth, TypeUser, ITransaction } from 'bakosafe';
import { FuelWalletLocked } from '@fuel-wallet/sdk';

import { IAccountKeys, IDefaultAccount, accounts } from '../mocks';
import axios, { AxiosInstance } from 'axios';
import { Wallet, Provider } from 'fuels';
export interface IAuthAccount extends IDefaultAccount {
  BakoSafeAuth: IBakoSafeAuth;
}
export interface IUserAuth {
  [key: string]: IAuthAccount;
}

// woking to local node just fine
export class AuthTestUtil {
  public BakoSafeAuth?: IBakoSafeAuth;
  public client: AxiosInstance;

  protected constructor({ address, token }: IBakoSafeAuth) {
    this.BakoSafeAuth = {
      address,
      token,
    };
    this.client = axios.create({
      baseURL: BakoSafe.getProviders('SERVER_URL'),
      headers: {
        Authorization: token,
        Signeraddress: address,
      },
    });
  }

  static async create(account: IAccountKeys, provider: string) {
    const address = accounts[account].address;
    const pk = accounts[account].privateKey;
    const client = axios.create({
      baseURL: BakoSafe.getProviders('SERVER_URL'),
    });
    const {
      data: { code },
    } = await client.post('/user', { address, provider, type: TypeUser.FUEL });

    if (!code) throw new Error('Account not created');

    const { data } = await client.post('/auth/sign-in', {
      digest: code,
      encoder: TypeUser.FUEL,
      signature: await AuthTestUtil.signerByPk(pk, code),
    });

    return new AuthTestUtil({
      address,
      token: data.accessToken,
    });
  }

  static async signerByPk(pk: string, code: string) {
    const signer = Wallet.fromPrivateKey(
      pk,
      await Provider.create(BakoSafe.getProviders('CHAIN_URL')),
    );
    const msg = await signer.signMessage(code);
    return msg;
  }

  static async signerByAccount(wallet: FuelWalletLocked, code: string) {
    const msg = await wallet.signMessage(code);
    return msg;
  }

  async signTransaction(
    wallet: FuelWalletLocked,
    BakoSafeAuthTransactionId: string,
    approve?: boolean,
  ) {
    const { data } = await this.client.get<ITransaction>(
      `/transaction/${BakoSafeAuthTransactionId}`,
    );
    const msg = await wallet.signMessage(data.hash);

    await this.client
      .put(`/transaction/signer/${BakoSafeAuthTransactionId}`, {
        account: wallet.address.toString(),
        signer: msg,
        confirm: approve ?? true,
      })
      .then(() => true)
      .catch(() => false);
  }
}

export const authService = async (
  _accounts: IAccountKeys[],
  provider: string,
) => {
  const result: { [key: string]: IAuthAccount } = {};
  for await (const acc of _accounts) {
    const account: IDefaultAccount = accounts[acc];
    const auth = await AuthTestUtil.create(acc, provider);

    result[acc] = {
      ...account,
      BakoSafeAuth: auth.BakoSafeAuth!,
    };
  }

  return result;
};
