import {
  IAuthCreateRequest,
  IAuthCreateResponse,
  IAuthSignRequest,
  IAuthSignResponse,
  ISelectWorkspaceResponse,
  IBakoSafeAuth,
} from 'bakosafe/src/api/auth/types';

export const mockAuthService = {
  auth: jest.fn<Promise<IAuthCreateResponse>, [IAuthCreateRequest]>(),
  sign: jest.fn<Promise<IAuthSignResponse>, [IAuthSignRequest]>(),
  selectWorkspace: jest.fn<Promise<ISelectWorkspaceResponse>, [string]>(),
  getWorkspaces: jest.fn<Promise<ISelectWorkspaceResponse[]>, []>(),
  setAuth: jest.fn<void, [IBakoSafeAuth]>(),
};

// Implementação dos mocks utilizando os parâmetros da request:
mockAuthService.auth.mockImplementation((params: IAuthCreateRequest) => {
  const { address, provider, type } = params;
  console.log(params);
  return new Promise((resolve, _) => {
    resolve({
      code: '',
      validAt: '',
      origin: '',
    });
  });
});

mockAuthService.sign.mockImplementation((params: IAuthSignRequest) => {
  const { digest, encoder, signature } = params;

  return new Promise((resolve, _) => {
    resolve({
      accessToken: '',
      address: '',
      avatar: '',
      user_id: '',
      workspace: { id: '', name: '', avatar: '' },
    });
  });
});

mockAuthService.selectWorkspace.mockImplementation((workspaceId: string) => {
  return new Promise((resolve, _) => {
    resolve({ id: '', name: '', avatar: '' });
  });
});

mockAuthService.getWorkspaces.mockImplementation(() => {
  return new Promise((resolve, _) => {
    resolve([{ id: '', name: '', avatar: '' }]);
  });
});

// Exporta o mock para ser usado nos testes
export default mockAuthService;
