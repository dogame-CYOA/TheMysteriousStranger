import { Connection, PublicKey } from '@solana/web3.js';

// Configuration - API key is hidden from frontend
const HELIUS_API_KEY = process.env.HELIUS_API_KEY;
if (!HELIUS_API_KEY) {
  throw new Error('HELIUS_API_KEY environment variable is required');
}
const HELIUS_RPC_URL = `https://rpc.helius.xyz/?api-key=${HELIUS_API_KEY}`;

// Security: Rate limiting
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW = 5 * 60 * 1000; // 5 minutes
const MAX_REQUESTS_PER_WINDOW = 5; // Lower limit for proxy

function checkRateLimit(identifier) {
  const now = Date.now();
  const key = `proxy_rate_limit_${identifier}`;
  const current = rateLimitStore.get(key) || { count: 0, expires: now + RATE_LIMIT_WINDOW };
  
  if (now > current.expires) {
    current.count = 1;
    current.expires = now + RATE_LIMIT_WINDOW;
  } else {
    current.count++;
  }
  
  rateLimitStore.set(key, current);
  return current.count <= MAX_REQUESTS_PER_WINDOW;
}

// Clean up rate limits
setInterval(() => {
  const now = Date.now();
  for (const [key, data] of rateLimitStore.entries()) {
    if (now > data.expires) {
      rateLimitStore.delete(key);
    }
  }
}, 5 * 60 * 1000);

// Security: Validate wallet address format
function isValidWalletAddress(address) {
  try {
    new PublicKey(address);
    return true;
  } catch {
    return false;
  }
}

// Security: Rate limiting
export default async function handler(req, res) {
  // Security: Restrict CORS to your domain only
  const allowedOrigins = [
    'https://the-mysterious-stranger.vercel.app',
    'http://localhost:3000',
    'http://127.0.0.1:3000'
  ];
  
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Request-Timestamp');
  
  // Security: Add security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  // Security: Request size limit (1MB)
  const contentLength = parseInt(req.headers['content-length'] || '0');
  if (contentLength > 1024 * 1024) {
    return res.status(413).json({
      success: false,
      error: 'Request too large'
    });
  }
  
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  
  // Security: Rate limiting
  const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
  if (!checkRateLimit(clientIP)) {
    return res.status(429).json({
      success: false,
      error: 'Rate limit exceeded. Please try again later.'
    });
  }
  
  // Security: Generate request ID for tracking
  const requestId = Math.random().toString(36).substring(2, 10);
  
  const { walletAddress, nftMintAddress, sessionToken } = req.body;
  
  // Security: Validate inputs
  if (!walletAddress || !nftMintAddress || !sessionToken) {
    console.log(`[${requestId}] Proxy request missing required parameters`);
    return res.status(400).json({
      success: false,
      error: 'Missing required parameters'
    });
  }
  
  // Security: Validate wallet address format
  if (!isValidWalletAddress(walletAddress) || !isValidWalletAddress(nftMintAddress)) {
    console.log(`[${requestId}] Invalid wallet or NFT address format`);
    return res.status(400).json({
      success: false,
      error: 'Invalid address format'
    });
  }
  
  // Security: Rate limiting per wallet
  if (!checkRateLimit(`proxy_wallet_${walletAddress}`)) {
    console.log(`[${requestId}] Rate limit exceeded for wallet: ${walletAddress.substring(0, 8)}...`);
    return res.status(429).json({
      success: false,
      error: 'Rate limit exceeded. Please try again later.'
    });
  }
  
  try {
    console.log(`[${requestId}] Querying NFT ownership for wallet: ${walletAddress.substring(0, 4)}...`);
    // SECURITY: Don't log API URLs or internal details
    
    const connection = new Connection(HELIUS_RPC_URL, 'confirmed');
    const tokenAccounts = await connection.getParsedTokenAccountsByOwner(
      new PublicKey(walletAddress),
      { mint: new PublicKey(nftMintAddress) }
    );

    const hasNFT = tokenAccounts.value.length > 0 &&
                   tokenAccounts.value.some(account =>
                     account.account.data.parsed.info.tokenAmount.uiAmount > 0
                   );

    console.log(`[${requestId}] NFT query result: ${hasNFT ? 'Found' : 'Not found'} for wallet: ${walletAddress.substring(0, 4)}...`);
    
    return res.status(200).json({ success: true, hasNFT });
  } catch (error) {
    // SECURITY: Don't log error details or stack traces
    console.error(`[${requestId}] Proxy NFT query error: ${error.name}`);
    return res.status(500).json({ 
      success: false, 
      error: 'Failed to query NFT ownership' 
    });
  }
}
