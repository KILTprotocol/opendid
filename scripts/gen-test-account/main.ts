import keyring from '@polkadot/ui-keyring';
import { cryptoWaitReady } from '@polkadot/util-crypto';
import { mnemonicGenerate } from '@polkadot/util-crypto';
import axios from 'axios';

cryptoWaitReady().then(async () => {
    keyring.loadAll({ ss58Format: 38, type: 'sr25519' });
    const mnemonic = mnemonicGenerate();
    const account = keyring.addUri(mnemonic);
    await axios.post('https://faucet-backend.peregrine.kilt.io/faucet/drop', { address: account.pair.address })
    console.log(mnemonic)
});