import {
  IAuthCreateRequest,
  IAuthCreateResponse,
  IAuthService,
  IAuthSignRequest,
  IAuthSignResponse,
  IBakoSafeAuth,
} from './types';

import { Api } from '../api';

export class AuthService extends Api implements IAuthService {
  constructor() {
    super();
  }

  public async setAuth(auth: IBakoSafeAuth) {
    this.client.defaults.headers['Authorization'] = auth.token;
    this.client.defaults.headers['Signeraddress'] = auth.address;
    return;
  }

  public async auth(params: IAuthCreateRequest): Promise<IAuthCreateResponse> {
    const { data } = await this.client.post('/user', params);
    return data;
  }

  public async sign(params: IAuthSignRequest): Promise<IAuthSignResponse> {
    const { data } = await this.client.post('/auth/sign-in', params);
    return data;
  }

  public async selectWorkspace(workspaceId: string) {
    if (!this.client.defaults.headers['Signeraddress'])
      throw new Error('Auth is required');

    const { data } = await this.client.put('/workspace', {
      workspaceId,
      userId: this.client.defaults.headers['Signeraddress'],
    });
    return data;
  }

  public async getWorkspaces() {
    if (!this.client.defaults.headers['Signeraddress'])
      throw new Error('Auth is required');
    const { data } = await this.client.get(`/workspace`);
    return data;
  }
}
