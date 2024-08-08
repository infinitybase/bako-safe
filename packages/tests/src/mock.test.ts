import { mockAuthService } from './mocks/api/auth';
import { TypeUser } from 'bakosafe/src/api/auth';

jest.mock('bakosafe/src/api/auth', () => {
  return {
    TypeUser: jest.requireActual('bakosafe/src/api/auth').TypeUser,
    AuthService: jest.fn().mockImplementation(() => mockAuthService),
  };
});

describe('AuthService Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should return admin token for admin user', async () => {
    console.log(TypeUser.FUEL);
    const response = await mockAuthService.auth({
      address: 'admin',
      provider: 'admin',
      type: TypeUser.FUEL,
    });
    console.log(response);
    expect(mockAuthService.auth).toHaveBeenCalledWith({
      username: 'admin',
      password: 'admin-pass',
    });
  });
});
