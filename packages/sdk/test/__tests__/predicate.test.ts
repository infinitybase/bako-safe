import { Provider } from 'fuels';
import { signin, newVault, IUserAuth, authService } from '../utils';
import { IPayloadVault, Vault } from '../../src/modules';
import { BSafe } from '../../configurables';
import {
  DEFAULT_BALANCES,
  accounts,
  DEFAULT_TRANSACTION_PAYLOAD,
} from '../mocks';

describe('[PREDICATES]', () => {
  let chainId: number;
  let auth: IUserAuth;
  let provider: Provider;
  let signers: string[];

  beforeAll(async () => {
    provider = await Provider.create(BSafe.get('PROVIDER'));
    chainId = await provider.getChainId();
    auth = await authService(
      ['USER_1', 'USER_2', 'USER_3', 'USER_5', 'USER_4'],
      provider.url,
    );
    signers = [
      accounts['USER_1'].address,
      accounts['USER_2'].address,
      accounts['USER_3'].address,
    ];
  }, 20 * 1000);

  test('Create an inválid vault', async () => {
    const VaultPayload: IPayloadVault = {
      configurable: {
        HASH_PREDICATE: undefined,
        SIGNATURES_COUNT: 3,
        SIGNERS: signers,
        network: provider.url,
        chainId: chainId,
      },
      provider,
      BSAFEAuth: auth['USER_1'].BSAFEAuth,
    };

    VaultPayload.configurable.SIGNATURES_COUNT = 0;

    await expect(Vault.create(VaultPayload)).rejects.toThrow(
      'SIGNATURES_COUNT is required must be granter than zero',
    );

    VaultPayload.configurable.SIGNATURES_COUNT = 3;
    VaultPayload.configurable.SIGNERS = [];
    await expect(Vault.create(VaultPayload)).rejects.toThrow(
      'SIGNERS must be greater than zero',
    );

    VaultPayload.configurable.SIGNERS = signers;
    VaultPayload.configurable.SIGNATURES_COUNT = 5;

    await expect(Vault.create(VaultPayload)).rejects.toThrow(
      'Required Signers must be less than signers',
    );
  });

  test('Created an valid vault', async () => {
    const vault = await newVault(signers, provider, auth['USER_1'].BSAFEAuth);
    expect(await vault.getBalances()).toStrictEqual(DEFAULT_BALANCES);
  });

  test(
    'Instance an old Vault by BSAFEPredicate ID',
    async () => {
      const vault = await newVault(signers, provider, auth['USER_1'].BSAFEAuth);
      const auxVault = await Vault.create({
        ...auth['USER_1'].BSAFEAuth,
        id: vault.BSAFEVaultId,
      });
      expect(auxVault.BSAFEVaultId).toStrictEqual(vault.BSAFEVaultId);
      expect(auxVault.BSAFEVault.id).toStrictEqual(vault.BSAFEVaultId);
    },
    20 * 1000,
  );

  test(
    'Instance an old Vault by predicate address',
    async () => {
      const vault = await newVault(signers, provider, auth['USER_1'].BSAFEAuth);
      const auxVault = await Vault.create({
        ...auth['USER_1'].BSAFEAuth,
        predicateAddress: vault.address.toString(),
      });
      expect(auxVault.BSAFEVaultId).toStrictEqual(vault.BSAFEVaultId);
    },
    10 * 1000,
  );

  test(
    'Instance an old Vault by payload',
    async () => {
      const vault = await newVault(signers, provider, auth['USER_1'].BSAFEAuth);
      const providerByPayload = await Provider.create(
        vault.BSAFEVault.provider,
      );

      const vaultByPayload = await Vault.create({
        configurable: JSON.parse(vault.BSAFEVault.configurable),
        provider: providerByPayload,
      });

      const [vaultAddress, vaultByPayloadAddress] = [
        vault.address.toString(),
        vaultByPayload.address.toString(),
      ];

      expect(vaultAddress).toEqual(vaultByPayloadAddress);
    },
    10 * 1000,
  );

  test(
    'Find a transactions of predicate and return an list of Transfer instances',
    async () => {
      const vault = await newVault(
        signers,
        provider,
        auth['USER_1'].BSAFEAuth,
        5,
      );
      const tx_1 = DEFAULT_TRANSACTION_PAYLOAD(accounts['STORE'].address);
      const tx_2 = DEFAULT_TRANSACTION_PAYLOAD(accounts['STORE'].address);

      const transaction = await vault.BSAFEIncludeTransaction(tx_1);
      await vault.BSAFEIncludeTransaction(tx_2);

      await signin(
        transaction.getHashTxId(),
        'USER_2',
        auth['USER_2'].BSAFEAuth,
        transaction.BSAFETransactionId,
      );

      //default pagination
      const transactions = await vault.BSAFEGetTransactions();
      expect(transactions.data.length).toBe(2);
      expect(transactions.currentPage).toBe(0);
      expect(transactions.perPage).toBe(10);

      //custom pagination
      const perPage = 1;
      const page = 1;
      const ptransations = await vault.BSAFEGetTransactions({
        perPage,
        page,
      });
      expect(ptransations.currentPage).toBe(page);
      expect(ptransations.perPage).toBe(perPage);
      expect(ptransations.data.length).toBe(1);
    },
    100 * 1000,
  );

  test('Call an method of vault depends of auth without credentials', async () => {
    const vault = await newVault(signers, provider);

    await expect(vault.getConfigurable().SIGNATURES_COUNT).toBe(3);
    await expect(vault.BSAFEGetTransactions()).rejects.toThrow(
      'Auth is required',
    );
  });
});
