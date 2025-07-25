import { Connection, PublicKey } from '@solana/web3.js';

// Configuration
const REQUIRED_NFT_ADDRESS = 'Dh6isVXwKrNNamLjzQbFXk-BKPdiLK4hGJVjfft6ZooLJ';
const SOLANA_RPC_URL = 'https://api.mainnet-beta.solana.com';

export default async function handler(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { walletAddress } = req.body;

    if (!walletAddress) {
      return res.status(400).json({ 
        success: false, 
        error: 'Wallet address is required' 
      });
    }

    // Validate wallet address format
    let walletPublicKey;
    try {
      walletPublicKey = new PublicKey(walletAddress);
    } catch (error) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid wallet address format' 
      });
    }

    // Connect to Solana with better error handling
    const connection = new Connection(SOLANA_RPC_URL, {
      commitment: 'confirmed',
      confirmTransactionInitialTimeout: 60000
    });

    // Get all token accounts for the wallet
    const tokenAccounts = await connection.getParsedTokenAccountsByOwner(
      walletPublicKey,
      {
        programId: new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')
      }
    );

    // Extract NFT mint addresses
    const ownedNFTs = [];
    for (const account of tokenAccounts.value) {
      const tokenAmount = account.account.data.parsed.info.tokenAmount;
      
      // NFTs typically have 0 decimals and amount of 1
      if (tokenAmount.decimals === 0 && tokenAmount.uiAmount === 1) {
        const mintAddress = account.account.data.parsed.info.mint;
        ownedNFTs.push(mintAddress);
      }
    }

    // Check if required NFT is owned
    const hasRequiredNFT = ownedNFTs.includes(REQUIRED_NFT_ADDRESS);

    if (hasRequiredNFT) {
      // Generate a session token (simple approach)
      const sessionToken = Buffer.from(`${walletAddress}-${Date.now()}`).toString('base64');
      
      return res.status(200).json({
        success: true,
        message: 'NFT ownership verified',
        sessionToken: sessionToken,
        walletAddress: walletAddress
      });
    } else {
      return res.status(403).json({
        success: false,
        error: 'Required NFT not found in wallet',
        ownedCount: ownedNFTs.length
      });
    }

  } catch (error) {
    console.error('NFT verification error:', error);
    
    // Better error handling for different types of errors
    if (error.message?.includes('Invalid public key')) {
      return res.status(400).json({
        success: false,
        error: 'Invalid wallet address provided'
      });
    }
    
    if (error.message?.includes('Network request failed')) {
      return res.status(503).json({
        success: false,
        error: 'Solana network temporarily unavailable'
      });
    }
    
    return res.status(500).json({
      success: false,
      error: 'Internal server error during verification'
    });
  }
}
