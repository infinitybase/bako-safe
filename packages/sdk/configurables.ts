export const defaultConfig = {
  CHAIN_URL: 'http://localhost:4000/v1/graphql',
  SERVER_URL: 'http://localhost:3333/',
  CLIENT_URL: 'https://safe.bako.global',
  ENCODER: 'Fuel',
  SIGNATURE_PREFIX: '0x42414b4f',
};

export const gasConfig = {
  GAS_LIMIT: 10000000,
  MAX_FEE: 1000000, // todo: check this value, required more low value
  BASE_FEE: 0.0001, // todo: check this value, is a fee for transaction, with assetid equal of base assetid of chain -> equal of min mock value to transaction sends
};

const unEditable = ['ENCODER'];

export type DefaultConfigurables = typeof defaultConfig;
export type DefaultConfigurablesKeys = keyof DefaultConfigurables;
export type GasConfigurables = typeof gasConfig;
export type GasConfigurablesKeys = keyof GasConfigurables;

export const BakoSafe = {
  setProviders: (params: Partial<DefaultConfigurables>) => {
    const configurableKeys = Object.keys(params);

    configurableKeys.forEach((key) => {
      if (key in defaultConfig && !unEditable.includes(key)) {
        // @ts-ignore
        defaultConfig[key] = params[key]!;
      }
    });
  },
  setGasConfig: (params: Partial<GasConfigurables>) => {
    const configurableKeys = Object.keys(params);

    configurableKeys.forEach((key) => {
      if (key in gasConfig) {
        // @ts-ignore
        gasConfig[key] = params[key]!;
      }
    });
  },
  getProviders: (key: DefaultConfigurablesKeys) => defaultConfig[key],
  getGasConfig: (key: GasConfigurablesKeys): number => gasConfig[key],
};
