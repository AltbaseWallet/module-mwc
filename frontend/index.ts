import { defineCoinModule } from '../../../src/coin-modules/types'
export default defineCoinModule({
  id: 'mwc', name: 'MimbleWimbleCoin', ticker: 'MWC', networkId: 'mwc-mainnet',
  supportsMemo: false, satsPerCoin: 1000000000, walletEngine: 'mwc-local',
}, 'mwc-sdk')
