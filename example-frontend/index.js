import { createRoot } from "react-dom/client";
import { App } from "./App";

window.kilt = window.kilt || {};
Object.defineProperty(window.kilt, 'meta', { 
    value: { versions: { credentials: '3.3' } }, 
    enumerable: false
})
window.dispatchEvent(new CustomEvent('kilt-dapp#initialized'))

const container = document.getElementById("app");
const root = createRoot(container)
root.render(<App />);