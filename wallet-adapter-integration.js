// Complete Wallet Adapter Integration for The Mysterious Stranger
// Browser-compatible version - no ES6 imports required

// Configuration
const SOLANA_RPC_ENDPOINT = 'https://api.mainnet-beta.solana.com';

// Complete wallet adapter manager
class WalletAdapterManager {
    constructor() {
        this.connectedWallet = null;
        this.connectedAdapter = null;
        this.isConnecting = false;
        this.listeners = new Set();
        this.initializeAdapters();
    }

    // Initialize all wallet adapters
    initializeAdapters() {
        // Check for available wallets in the browser
        this.availableWallets = this.detectAvailableWallets();
        console.log('Available wallets detected:', this.availableWallets.map(w => w.name));
    }

    // Detect available wallets in the browser
    detectAvailableWallets() {
        const wallets = [];
        
        // Check for Phantom
        if (window.solana && window.solana.isPhantom) {
            wallets.push({
                name: 'Phantom',
                adapter: window.solana,
                readyState: 'Installed'
            });
        }
        
        // Check for Solflare
        if (window.solflare) {
            wallets.push({
                name: 'Solflare',
                adapter: window.solflare,
                readyState: 'Installed'
            });
        }
        
        // Check for Backpack
        if (window.backpack) {
            wallets.push({
                name: 'Backpack',
                adapter: window.backpack,
                readyState: 'Installed'
            });
        }
        
        // Check for Slope
        if (window.solana && window.solana.isSlope) {
            wallets.push({
                name: 'Slope',
                adapter: window.solana,
                readyState: 'Installed'
            });
        }
        
        // Check for Glow
        if (window.solana && window.solana.isGlow) {
            wallets.push({
                name: 'Glow',
                adapter: window.solana,
                readyState: 'Installed'
            });
        }
        
        return wallets;
    }

    // Get available wallets
    getAvailableWallets() {
        return this.availableWallets;
    }

    // Get wallet by name
    getWalletByName(name) {
        return this.availableWallets.find(w => w.name === name);
    }

    // Connect to a specific wallet
    async connectToWallet(walletName) {
        if (this.isConnecting) {
            throw new Error('Already connecting to wallet');
        }

        this.isConnecting = true;

        try {
            const wallet = this.getWalletByName(walletName);
            if (!wallet) {
                throw new Error(`Wallet ${walletName} not found`);
            }

            console.log(`Attempting to connect to ${walletName}...`);
            
            // Connect to wallet
            let response;
            try {
                response = await wallet.adapter.connect();
            } catch (error) {
                // Handle different connection methods for mobile wallets
                if (typeof wallet.adapter.request === 'function') {
                    response = await wallet.adapter.request({ method: 'connect' });
                } else if (typeof wallet.adapter.enable === 'function') {
                    response = await wallet.adapter.enable();
                } else {
                    throw error;
                }
            }
            
            // Extract wallet address with enhanced Solflare support
            let walletAddress;
            console.log(`[${walletName}] Connection response:`, response);
            console.log(`[${walletName}] Response type:`, typeof response);
            console.log(`[${walletName}] Response keys:`, response ? Object.keys(response) : 'null');
            
            if (response.publicKey) {
                walletAddress = response.publicKey.toString();
            } else if (response.pubkey) {
                walletAddress = response.pubkey.toString();
            } else if (response.address) {
                walletAddress = response.address;
            } else if (response.account) {
                walletAddress = response.account;
            } else if (response.accounts && response.accounts[0]) {
                walletAddress = response.accounts[0];
            } else if (response.data && response.data.publicKey) {
                // Solflare specific format
                walletAddress = response.data.publicKey.toString();
            } else if (response.result && response.result.publicKey) {
                // Alternative Solflare format
                walletAddress = response.result.publicKey.toString();
            } else if (typeof response === 'string') {
                walletAddress = response;
            } else if (response && typeof response === 'object') {
                // Try to find any property that looks like a public key
                for (const key in response) {
                    const value = response[key];
                    if (value && typeof value === 'string' && value.length >= 32 && value.length <= 44) {
                        // Check if it looks like a Solana address
                        if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value)) {
                            walletAddress = value;
                            break;
                        }
                    }
                }
            }
            
            if (!walletAddress) {
                console.error(`[${walletName}] Could not extract wallet address. Response:`, response);
                throw new Error('Could not extract wallet address from response');
            }
            
            this.connectedWallet = walletAddress;
            this.connectedAdapter = wallet.adapter;
            
            console.log(`Successfully connected to ${walletName}: ${this.connectedWallet.substring(0, 8)}...`);
            
            return {
                success: true,
                wallet: walletName,
                address: this.connectedWallet,
                adapter: wallet.adapter
            };
        } catch (error) {
            console.error(`Wallet connection error (${walletName}):`, error);
            throw error;
        } finally {
            this.isConnecting = false;
        }
    }

    // Auto-connect to first available wallet
    async autoConnect() {
        const availableWallets = this.getAvailableWallets();
        
        if (availableWallets.length === 0) {
            throw new Error('No supported wallets detected. Please install Phantom, Solflare, or Backpack.');
        }

        // Try to connect to the first available wallet (usually Phantom)
        const walletToConnect = availableWallets[0];
        return await this.connectToWallet(walletToConnect.name);
    }

    // Sign message using wallet adapter
    async signMessage(message) {
        if (!this.connectedAdapter) {
            throw new Error('No wallet connected');
        }

        try {
            console.log('Signing message with wallet adapter...');
            const encodedMessage = new TextEncoder().encode(message);
            
            let signature;
            
            // Try different signing methods
            if (typeof this.connectedAdapter.signMessage === 'function') {
                try {
                    const result = await this.connectedAdapter.signMessage(encodedMessage, 'utf8');
                    signature = result.signature;
                } catch (error) {
                    console.log('UTF8 encoding failed, trying without...');
                    const result = await this.connectedAdapter.signMessage(encodedMessage);
                    signature = result.signature;
                }
            } else if (typeof this.connectedAdapter.sign === 'function') {
                const result = await this.connectedAdapter.sign(encodedMessage);
                signature = result.signature;
            } else {
                throw new Error('Wallet does not support message signing');
            }
            
            // Convert signature to base58
            if (signature instanceof Uint8Array) {
                return this.base58Encode(signature);
            } else if (typeof signature === 'string') {
                return signature;
            } else {
                throw new Error('Unsupported signature format');
            }
        } catch (error) {
            console.error('Message signing error:', error);
            throw error;
        }
    }

    // Disconnect wallet
    disconnect() {
        if (this.connectedAdapter && typeof this.connectedAdapter.disconnect === 'function') {
            this.connectedAdapter.disconnect();
        }
        this.handleDisconnect();
    }

    // Handle wallet disconnection
    handleDisconnect() {
        this.connectedWallet = null;
        this.connectedAdapter = null;
        this.notifyListeners('disconnected');
        console.log('Wallet disconnected');
    }

    // Get connection status
    isConnected() {
        return this.connectedAdapter && this.connectedWallet;
    }

    // Get connected wallet address
    getConnectedAddress() {
        return this.connectedWallet;
    }

    // Get connected wallet name
    getConnectedWalletName() {
        if (!this.connectedAdapter) return null;
        
        // Find the wallet name by matching the adapter
        const wallet = this.availableWallets.find(w => w.adapter === this.connectedAdapter);
        return wallet ? wallet.name : 'Unknown';
    }

    // Event listener system
    addListener(callback) {
        this.listeners.add(callback);
    }

    removeListener(callback) {
        this.listeners.delete(callback);
    }

    notifyListeners(event, data) {
        this.listeners.forEach(callback => {
            try {
                callback(event, data);
            } catch (error) {
                console.error('Listener error:', error);
            }
        });
    }

    // Base58 encoding utility
    base58Encode(bytes) {
        const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        let num = 0n;
        for (let i = 0; i < bytes.length; i++) {
            num = num * 256n + BigInt(bytes[i]);
        }
        let str = '';
        while (num > 0n) {
            str = alphabet[Number(num % 58n)] + str;
            num = num / 58n;
        }
        // Handle leading zeros
        for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
            str = '1' + str;
        }
        return str;
    }

    // Get wallet installation links
    getInstallationLinks() {
        return {
            'Phantom': 'https://phantom.app/',
            'Solflare': 'https://solflare.com/',
            'Backpack': 'https://backpack.app/',
            'Slope': 'https://slope.finance/',
            'Glow': 'https://glow.app/'
        };
    }

    // Check if a specific wallet is installed
    isWalletInstalled(walletName) {
        const wallet = this.getWalletByName(walletName);
        return wallet && wallet.readyState === 'Installed';
    }
}

// Create global instance
const walletManager = new WalletAdapterManager();

// Make it globally available
window.walletManager = walletManager; 
