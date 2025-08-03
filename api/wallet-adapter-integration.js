// Complete Wallet Adapter Integration for The Mysterious Stranger
// This replaces manual wallet detection with the official Solana Wallet Adapter

import { Connection, PublicKey } from '@solana/web3.js';
import { 
    PhantomWalletAdapter,
    SolflareWalletAdapter,
    BackpackWalletAdapter,
    SlopeWalletAdapter,
    GlowWalletAdapter
} from '@solana/wallet-adapter-wallets';

// Configuration
const SOLANA_RPC_ENDPOINT = 'https://api.mainnet-beta.solana.com';
const connection = new Connection(SOLANA_RPC_ENDPOINT);

// Initialize wallet adapters
const wallets = [
    new PhantomWalletAdapter(),
    new SolflareWalletAdapter(),
    new BackpackWalletAdapter(),
    new SlopeWalletAdapter(),
    new GlowWalletAdapter()
];

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
        wallets.forEach(wallet => {
            // Set up disconnect listeners
            wallet.on('disconnect', () => {
                this.handleDisconnect();
            });
            
            // Set up connect listeners
            wallet.on('connect', () => {
                if (wallet.connected && wallet.publicKey) {
                    this.connectedWallet = wallet.publicKey.toString();
                    this.connectedAdapter = wallet;
                    this.notifyListeners('connected', {
                        wallet: wallet.name,
                        address: this.connectedWallet
                    });
                }
            });
        });
    }

    // Get available wallets
    getAvailableWallets() {
        return wallets.filter(wallet => 
            wallet.readyState === 'Installed' || 
            wallet.readyState === 'Loadable'
        );
    }

    // Get wallet by name
    getWalletByName(name) {
        return wallets.find(w => w.name === name);
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
            await wallet.connect();
            
            if (wallet.connected && wallet.publicKey) {
                this.connectedWallet = wallet.publicKey.toString();
                this.connectedAdapter = wallet;
                
                console.log(`Successfully connected to ${walletName}: ${this.connectedWallet.substring(0, 8)}...`);
                
                return {
                    success: true,
                    wallet: walletName,
                    address: this.connectedWallet,
                    adapter: wallet
                };
            } else {
                throw new Error('Failed to connect to wallet');
            }
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
        if (!this.connectedAdapter || !this.connectedAdapter.connected) {
            throw new Error('No wallet connected');
        }

        try {
            console.log('Signing message with wallet adapter...');
            const encodedMessage = new TextEncoder().encode(message);
            const signature = await this.connectedAdapter.signMessage(encodedMessage);
            
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
        if (this.connectedAdapter) {
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
        return this.connectedAdapter && this.connectedAdapter.connected;
    }

    // Get connected wallet address
    getConnectedAddress() {
        return this.connectedWallet;
    }

    // Get connected wallet name
    getConnectedWalletName() {
        return this.connectedAdapter ? this.connectedAdapter.name : null;
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
        return wallet && (wallet.readyState === 'Installed' || wallet.readyState === 'Loadable');
    }
}

// Create global instance
const walletManager = new WalletAdapterManager();

// Export for module usage
export default walletManager; 
