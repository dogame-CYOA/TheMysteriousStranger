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
        
        // Enhanced Solflare detection - multiple methods
        if (window.solflare) {
            console.log('Solflare detected via window.solflare');
            wallets.push({
                name: 'Solflare',
                adapter: window.solflare,
                readyState: 'Installed'
            });
        } else if (window.solana && window.solana.isSolflare) {
            console.log('Solflare detected via window.solana.isSolflare');
            wallets.push({
                name: 'Solflare',
                adapter: window.solana,
                readyState: 'Installed'
            });
        } else if (window.solflare && window.solflare.solana) {
            console.log('Solflare detected via window.solflare.solana');
            wallets.push({
                name: 'Solflare',
                adapter: window.solflare.solana,
                readyState: 'Installed'
            });
        }
        
        // Check for mobile Solflare via ethereum provider
        if (window.ethereum && window.ethereum.isSolflare) {
            console.log('Mobile Solflare detected via ethereum provider');
            wallets.push({
                name: 'Solflare',
                adapter: window.ethereum,
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
        } else if (window.solana && window.solana.isBackpack) {
            wallets.push({
                name: 'Backpack',
                adapter: window.solana,
                readyState: 'Installed'
            });
        } else if (window.backpack && window.backpack.solana) {
            wallets.push({
                name: 'Backpack',
                adapter: window.backpack.solana,
                readyState: 'Installed'
            });
        }
        
        // Check for mobile Backpack via ethereum provider
        if (window.ethereum && window.ethereum.isBackpack) {
            console.log('Mobile Backpack detected via ethereum provider');
            wallets.push({
                name: 'Backpack',
                adapter: window.ethereum,
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
        
        // Remove duplicates (same wallet detected multiple ways)
        const uniqueWallets = [];
        const seenNames = new Set();
        
        for (const wallet of wallets) {
            if (!seenNames.has(wallet.name)) {
                seenNames.add(wallet.name);
                uniqueWallets.push(wallet);
            }
        }
        
        return uniqueWallets;
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
            
            // Special handling for Solflare
            if (walletName === 'Solflare') {
                return await this.connectToSolflare(wallet);
            }
            
            // Connect to other wallets
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
            
            // Extract wallet address
            const walletAddress = this.extractWalletAddress(response, walletName);
            
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

    // Special Solflare connection handling
    async connectToSolflare(wallet) {
        console.log('Using Solflare-specific connection logic...');
        
        let response;
        const adapter = wallet.adapter;
        
        try {
            console.log('Solflare adapter available methods:', Object.getOwnPropertyNames(adapter));
            
            // Try multiple connection methods for Solflare
            if (typeof adapter.connect === 'function') {
                console.log('Trying Solflare connect() method...');
                response = await adapter.connect();
            } else if (typeof adapter.request === 'function') {
                console.log('Trying Solflare request() method...');
                response = await adapter.request({ method: 'connect' });
            } else if (typeof adapter.enable === 'function') {
                console.log('Trying Solflare enable() method...');
                response = await adapter.enable();
            } else if (adapter.solana && typeof adapter.solana.connect === 'function') {
                console.log('Trying Solflare via adapter.solana.connect()...');
                response = await adapter.solana.connect();
            } else if (window.solana && window.solana.isSolflare && typeof window.solana.connect === 'function') {
                console.log('Trying Solflare via window.solana.connect()...');
                response = await window.solana.connect();
            } else {
                console.error('Available adapter methods:', Object.getOwnPropertyNames(adapter));
                throw new Error('No supported Solflare connection method found');
            }
            
            console.log('Solflare connection response:', response);
            console.log('Response type:', typeof response);
            console.log('Response keys:', response ? Object.keys(response) : 'null');
            
            // Extract wallet address with comprehensive Solflare support
            const walletAddress = this.extractSolflareAddress(response);
            
            this.connectedWallet = walletAddress;
            this.connectedAdapter = adapter;
            
            console.log(`Successfully connected to Solflare: ${this.connectedWallet.substring(0, 8)}...`);
            
            return {
                success: true,
                wallet: 'Solflare',
                address: this.connectedWallet,
                adapter: adapter
            };
            
        } catch (error) {
            console.error('Solflare connection error:', error);
            
            // Try alternative connection approach for mobile Solflare
            if (error.message.includes('Plugin Closed') || error.message.includes('Failed to connect')) {
                console.log('Trying alternative Solflare connection method...');
                
                try {
                    // Wait a bit before retry
                    await new Promise(resolve => setTimeout(resolve, 1000));
                    
                    if (typeof adapter.request === 'function') {
                        response = await adapter.request({ 
                            method: 'connect',
                            params: []
                        });
                    } else if (typeof adapter.enable === 'function') {
                        response = await adapter.enable();
                    } else {
                        throw new Error('No alternative Solflare connection methods available');
                    }
                    
                    const walletAddress = this.extractSolflareAddress(response);
                    this.connectedWallet = walletAddress;
                    this.connectedAdapter = adapter;
                    
                    console.log(`Alternative Solflare connection successful: ${this.connectedWallet.substring(0, 8)}...`);
                    
                    return {
                        success: true,
                        wallet: 'Solflare',
                        address: this.connectedWallet,
                        adapter: adapter
                    };
                    
                } catch (altError) {
                    console.error('Alternative Solflare connection also failed:', altError);
                    throw new Error('Failed to connect to Solflare. Please ensure the wallet app is open and try again.');
                }
            }
            
            throw error;
        }
    }

    // Extract wallet address from response
    extractWalletAddress(response, walletName) {
        let walletAddress;
        
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
        } else if (typeof response === 'string') {
            walletAddress = response;
        } else {
            console.error(`[${walletName}] Could not extract wallet address. Response:`, response);
            throw new Error('Could not extract wallet address from response');
        }
        
        return walletAddress;
    }

    // Extract Solflare-specific wallet address
    extractSolflareAddress(response) {
        console.log('=== SOLFLARE ADDRESS EXTRACTION DEBUG ===');
        console.log('Full response object:', JSON.stringify(response, null, 2));
        console.log('Response type:', typeof response);
        console.log('Response constructor:', response?.constructor?.name);
        console.log('Response prototype:', Object.getPrototypeOf(response));
        
        // Log all response properties
        if (response && typeof response === 'object') {
            console.log('Response properties:', Object.getOwnPropertyNames(response));
            console.log('Response keys:', Object.keys(response));
            for (const key in response) {
                console.log(`  ${key}:`, response[key], `(${typeof response[key]})`);
            }
        }
        
        let walletAddress;
        
        // Try all possible Solflare response formats with enhanced logging
        if (response && response.publicKey) {
            console.log('✓ Found response.publicKey:', response.publicKey);
            if (typeof response.publicKey.toString === 'function') {
                walletAddress = response.publicKey.toString();
                console.log('✓ Converted publicKey to string:', walletAddress);
            } else if (typeof response.publicKey === 'string') {
                walletAddress = response.publicKey;
                console.log('✓ publicKey is already string:', walletAddress);
            }
        } else if (response && response.pubkey) {
            console.log('✓ Found response.pubkey:', response.pubkey);
            walletAddress = typeof response.pubkey.toString === 'function' ? response.pubkey.toString() : response.pubkey;
        } else if (response && response.address) {
            console.log('✓ Found response.address:', response.address);
            walletAddress = response.address;
        } else if (response && response.account) {
            console.log('✓ Found response.account:', response.account);
            walletAddress = response.account;
        } else if (response && response.accounts && response.accounts[0]) {
            console.log('✓ Found response.accounts[0]:', response.accounts[0]);
            walletAddress = response.accounts[0];
        } else if (response && response.data && response.data.publicKey) {
            console.log('✓ Found response.data.publicKey:', response.data.publicKey);
            walletAddress = typeof response.data.publicKey.toString === 'function' ? response.data.publicKey.toString() : response.data.publicKey;
        } else if (response && response.result && response.result.publicKey) {
            console.log('✓ Found response.result.publicKey:', response.result.publicKey);
            walletAddress = typeof response.result.publicKey.toString === 'function' ? response.result.publicKey.toString() : response.result.publicKey;
        } else if (response && response.data && response.data.address) {
            console.log('✓ Found response.data.address:', response.data.address);
            walletAddress = response.data.address;
        } else if (response && response.result && response.result.address) {
            console.log('✓ Found response.result.address:', response.result.address);
            walletAddress = response.result.address;
        } else if (typeof response === 'string') {
            console.log('✓ Response is string:', response);
            walletAddress = response;
        } else if (response && typeof response === 'object') {
            // Enhanced deep search with detailed logging
            console.log('🔍 Performing enhanced deep search for Solana address...');
            walletAddress = this.findSolanaAddressInObject(response);
            if (walletAddress) {
                console.log('✓ Found address in deep search:', walletAddress);
            } else {
                console.log('❌ Deep search failed to find valid address');
            }
        }
        
        console.log('Final extracted wallet address:', walletAddress);
        
        if (!walletAddress) {
            console.error('❌ SOLFLARE ADDRESS EXTRACTION FAILED');
            console.error('Response was:', response);
            console.error('Available properties:', response ? Object.keys(response) : 'none');
            throw new Error('Could not extract wallet address from Solflare response');
        }
        
        // Validate the address format
        console.log('Validating address format:', walletAddress);
        if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(walletAddress)) {
            console.error('❌ Invalid Solana address format:', walletAddress);
            console.error('Address length:', walletAddress.length);
            console.error('Address characters:', walletAddress.split(''));
            throw new Error('Invalid wallet address format received from Solflare');
        }
        
        console.log('✅ Solflare address extraction successful:', walletAddress);
        return walletAddress;
    }

    // Enhanced deep search for Solana address in object
    findSolanaAddressInObject(obj, depth = 0) {
        if (depth > 3) {
            console.log(`🔍 Stopping deep search at depth ${depth} to prevent infinite recursion`);
            return null;
        }
        
        console.log(`🔍 Deep search at depth ${depth}, object:`, obj);
        
        for (const key in obj) {
            const value = obj[key];
            console.log(`🔍 Checking key "${key}":`, value, `(${typeof value})`);
            
            if (value && typeof value === 'string' && value.length >= 32 && value.length <= 44) {
                console.log(`🔍 Found string with valid length: "${value}"`);
                // Check if it looks like a Solana address
                if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value)) {
                    console.log(`✅ Found valid Solana address: ${value}`);
                    return value;
                } else {
                    console.log(`❌ String doesn't match Solana address pattern: ${value}`);
                }
            } else if (value && typeof value === 'object' && depth < 3) {
                console.log(`🔍 Recursing into object at key "${key}"`);
                const found = this.findSolanaAddressInObject(value, depth + 1);
                if (found) {
                    console.log(`✅ Found address in nested object: ${found}`);
                    return found;
                }
            }
        }
        
        console.log(`❌ No valid address found at depth ${depth}`);
        return null;
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
            const walletName = this.getConnectedWalletName();
            
            // Solflare-specific signing
            if (walletName === 'Solflare') {
                console.log('Using Solflare-specific signing logic...');
                
                if (typeof this.connectedAdapter.signMessage === 'function') {
                    try {
                        // Try standard Solflare signing
                        const result = await this.connectedAdapter.signMessage(encodedMessage, 'utf8');
                        signature = result.signature;
                    } catch (error) {
                        console.log('Solflare UTF8 signing failed, trying without encoding...');
                        try {
                            const result = await this.connectedAdapter.signMessage(encodedMessage);
                            signature = result.signature;
                        } catch (error2) {
                            console.log('Solflare standard signing failed, trying alternative...');
                            // Some Solflare versions might use different method signatures
                            const result = await this.connectedAdapter.signMessage(message);
                            signature = result.signature;
                        }
                    }
                } else if (typeof this.connectedAdapter.sign === 'function') {
                    console.log('Using Solflare sign() method...');
                    const result = await this.connectedAdapter.sign(encodedMessage);
                    signature = result.signature;
                } else if (this.connectedAdapter.solana && typeof this.connectedAdapter.solana.signMessage === 'function') {
                    console.log('Using Solflare via adapter.solana.signMessage()...');
                    const result = await this.connectedAdapter.solana.signMessage(encodedMessage, 'utf8');
                    signature = result.signature;
                } else {
                    throw new Error('Solflare wallet does not support message signing');
                }
            } else {
                // Generic signing for other wallets
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
