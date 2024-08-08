export const networks: { [key: string]: string } = {
  BETA_5: 'https://beta-5.fuel.network/graphql',
  LOCAL: 'http://127.0.0.1:4000/v1/graphql',
  DEVNET: 'https://testnet.fuel.network/v1/graphql',
};

export type INetworkKeys = keyof typeof networks;
