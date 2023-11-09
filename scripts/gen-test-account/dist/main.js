"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const ui_keyring_1 = __importDefault(require("@polkadot/ui-keyring"));
const util_crypto_1 = require("@polkadot/util-crypto");
const util_crypto_2 = require("@polkadot/util-crypto");
const axios_1 = __importDefault(require("axios"));
(0, util_crypto_1.cryptoWaitReady)().then(async () => {
    ui_keyring_1.default.loadAll({ ss58Format: 38, type: 'sr25519' });
    const mnemonic = (0, util_crypto_2.mnemonicGenerate)();
    const account = ui_keyring_1.default.addUri(mnemonic);
    await axios_1.default.post('https://faucet-backend.peregrine.kilt.io/faucet/drop', { address: account.pair.address });
    console.log(mnemonic);
});
