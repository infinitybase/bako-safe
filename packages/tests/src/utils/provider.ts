import { Provider } from 'fuels';
import { BakoSafe } from 'bakosafe';

export class LocalProvider extends Provider {
  constructor() {
    super(BakoSafe.getProviders('CHAIN_URL'));
  }
}
