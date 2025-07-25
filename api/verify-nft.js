import { Connection, PublicKey } from '@solana/web3.js';

// Configuration - Your NFT address (the actual mint address)
const REQUIRED_NFT_ADDRESS = 'Dh6isVXwKrNNamLjzQbFXkBKPdiLk4hGJVjfft6ZooLJ';
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
    
    // Connect to Solana
    const connection = new Connection(SOLANA_RPC_URL, {
      commitment: 'confirmed',
      confirmTransactionInitialTimeout: 60000
    });
    
    // Method 1: Get all token accounts (original method)
    const tokenAccounts = await connection.getParsedTokenAccountsByOwner(
      walletPublicKey,
      {
        programId: new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')
      }
    );
    
    // Extract all tokens (not just NFTs) for debugging
    const allTokens = [];
    const potentialNFTs = [];
    
    for (const account of tokenAccounts.value) {
      const tokenInfo = account.account.data.parsed.info;
      const tokenAmount = tokenInfo.tokenAmount;
      const mintAddress = tokenInfo.mint;
      
      allTokens.push({
        mint: mintAddress,
        amount: tokenAmount.uiAmount,
        decimals: tokenAmount.decimals
      });
      
      // Check different NFT criteria
      if (tokenAmount.decimals === 0 && tokenAmount.uiAmount === 1) {
        potentialNFTs.push(mintAddress);
      }
      
      // Also check for tokens with amount > 0 (some NFTs might have different criteria)
      if (tokenAmount.uiAmount > 0) {
        potentialNFTs.push(mintAddress);
      }
    }
    
    // Method 2: Direct check for the specific NFT
    let hasSpecificNFT = false;
    try {
      const specificTokenAccounts = await connection.getParsedTokenAccountsByOwner(
        walletPublicKey,
        {
          mint: new PublicKey(REQUIRED_NFT_ADDRESS)
        }
      );
      
      hasSpecificNFT = specificTokenAccounts.value.length > 0 && 
                      specificTokenAccounts.value.some(account => 
                        account.account.data.parsed.info.tokenAmount.uiAmount > 0
                      );
    } catch (error) {
      console.log('Direct NFT check failed:', error.message);
    }
    
    // Check if required NFT is owned using both methods
    const hasRequiredNFT = potentialNFTs.includes(REQUIRED_NFT_ADDRESS) || hasSpecificNFT;
    
    if (hasRequiredNFT) {
      // Generate a session token
      const sessionToken = Buffer.from(`${walletAddress}-${Date.now()}`).toString('base64');
      
      return res.status(200).json({
        success: true,
        message: 'NFT ownership verified',
        sessionToken: sessionToken,
        walletAddress: walletAddress,
        debug: {
          totalTokens: allTokens.length,
          potentialNFTs: potentialNFTs.length,
          hasSpecificNFT: hasSpecificNFT,
          method: hasSpecificNFT ? 'direct_check' : 'token_scan'
        }
      });
    } else {
      return res.status(403).json({
        success: false,
        error: 'Required NFT not found in wallet',
        requiredNFT: REQUIRED_NFT_ADDRESS,
        debug: {
          totalTokensFound: allTokens.length,
          potentialNFTsFound: potentialNFTs.length,
          hasSpecificNFT: hasSpecificNFT,
          // Show first 10 tokens for debugging (don't expose all for privacy)
          sampleTokens: allTokens.slice(0, 10),
          // Check if the required NFT is close to any found tokens
          closestMatches: potentialNFTs.filter(nft => 
            nft.substring(0, 10) === REQUIRED_NFT_ADDRESS.substring(0, 10)
          )
        }
      });
    }
    
  } catch (error) {
    console.error('NFT verification error:', error);
    
    return res.status(500).json({
      success: false,
      error: 'Internal server error during verification',
      details: error.message
    });
  }
}
