import { Connection, PublicKey } from '@solana/web3.js';
import crypto from 'crypto';

// Configuration
const REQUIRED_NFT_ADDRESS = 'Dh6isVXwKrNNamLjzQbFXkBKPdiLk4hGJVjfft6ZooLJ';
const SOLANA_RPC_URL = 'https://api.mainnet-beta.solana.com';
const SESSION_SECRET = process.env.SESSION_SECRET || 'kjnj32nejddlkM!#I*Rnlajknjnfsdf049857';
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours

// Simple in-memory session store (use Redis in production)
const activeSessions = new Map();

// Clean up expired sessions periodically
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of activeSessions.entries()) {
    if (now > session.expires) {
      activeSessions.delete(token);
    }
  }
}, 5 * 60 * 1000); // Clean every 5 minutes

function generateSecureToken(walletAddress) {
  const timestamp = Date.now();
  const data = `${walletAddress}-${timestamp}-${Math.random()}`;
  const hash = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('hex');
  return `${Buffer.from(data).toString('base64')}.${hash}`;
}

function verifySessionToken(token) {
  try {
    if (!token) return null;
    
    const [dataB64, hash] = token.split('.');
    if (!dataB64 || !hash) return null;
    
    const data = Buffer.from(dataB64, 'base64').toString();
    const expectedHash = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('hex');
    
    if (hash !== expectedHash) return null;
    
    const session = activeSessions.get(token);
    if (!session || Date.now() > session.expires) {
      activeSessions.delete(token);
      return null;
    }
    
    return session;
  } catch (error) {
    return null;
  }
}

export default async function handler(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  // Handle session verification (GET request)
  if (req.method === 'GET') {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace('Bearer ', '');
    
    const session = verifySessionToken(token);
    if (session) {
      return res.status(200).json({
        success: true,
        valid: true,
        walletAddress: session.walletAddress,
        expires: session.expires
      });
    } else {
      return res.status(401).json({
        success: false,
        valid: false,
        error: 'Invalid or expired session'
      });
    }
  }
  
  // Handle NFT verification (POST request)
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
    
    // Rate limiting: check if this wallet has been verified recently
    const recentAttempt = Array.from(activeSessions.values()).find(
      session => session.walletAddress === walletAddress && 
      Date.now() - session.created < 5 * 60 * 1000 // 5 minutes
    );
    
    if (recentAttempt) {
      return res.status(429).json({
        success: false,
        error: 'Too many verification attempts. Please wait a few minutes.'
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
    
    // Direct check for the specific NFT
    let hasRequiredNFT = false;
    try {
      const tokenAccounts = await connection.getParsedTokenAccountsByOwner(
        walletPublicKey,
        {
          mint: new PublicKey(REQUIRED_NFT_ADDRESS)
        }
      );
      
      hasRequiredNFT = tokenAccounts.value.length > 0 && 
                      tokenAccounts.value.some(account => 
                        account.account.data.parsed.info.tokenAmount.uiAmount > 0
                      );
    } catch (error) {
      console.error('NFT verification error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to verify NFT ownership'
      });
    }
    
    if (hasRequiredNFT) {
      // Generate secure session token
      const sessionToken = generateSecureToken(walletAddress);
      const expires = Date.now() + SESSION_DURATION;
      
      // Store session
      activeSessions.set(sessionToken, {
        walletAddress,
        created: Date.now(),
        expires,
        verified: true
      });
      
      return res.status(200).json({
        success: true,
        message: 'NFT ownership verified',
        sessionToken: sessionToken,
        expires: expires
      });
    } else {
      return res.status(403).json({
        success: false,
        error: 'Required NFT not found in wallet'
      });
    }
    
  } catch (error) {
    console.error('Verification error:', error);
    return res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
}
