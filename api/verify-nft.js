import { Connection, PublicKey } from '@solana/web3.js';
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import crypto from 'crypto';

// Configuration
const REQUIRED_NFT_ADDRESSES = [
  'Dh6isVXwKrNNamLjzQbFXkBKPdiLk4hGJVjfft6ZooLJ',
  '44K6Cr5YvpZLdSrDbJmwRi74c2szTLRtvf5Gr8e5tdQc'
];
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const AUTHENTICATED_SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours for authenticated users
const BROWSING_SESSION_DURATION = 2 * 60 * 60 * 1000; // 2 hours for browsing users
const REQUEST_SIGNING_SECRET = process.env.REQUEST_SIGNING_SECRET || crypto.randomBytes(32).toString('hex');

// Security: Enhanced rate limiting with different limits for different actions
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW = 5 * 60 * 1000; // 5 minutes
const MAX_REQUESTS_PER_WINDOW = 10;
const MAX_CHALLENGE_REQUESTS = 5; // Stricter limit for challenge generation
const MAX_BROWSING_REQUESTS = 3; // Very strict limit for browsing sessions

// Security: Session and challenge management
const activeSessions = new Map();
const pendingChallenges = new Map();
const failedAttempts = new Map(); // Track failed authentication attempts

// Security: Clean up expired sessions, challenges, rate limits, and failed attempts
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of activeSessions.entries()) {
    if (now > session.expires) {
      activeSessions.delete(token);
    }
  }
  for (const [challenge, data] of pendingChallenges.entries()) {
    if (now > data.expires) {
      pendingChallenges.delete(challenge);
    }
  }
  for (const [key, data] of rateLimitStore.entries()) {
    if (now > data.expires) {
      rateLimitStore.delete(key);
    }
  }
  for (const [key, data] of failedAttempts.entries()) {
    if (now > data.expires) {
      failedAttempts.delete(key);
    }
  }
}, 5 * 60 * 1000);

// Security: Enhanced rate limiting function with different limits
function checkRateLimit(identifier, type = 'general') {
  const now = Date.now();
  const key = `rate_limit_${type}_${identifier}`;
  const current = rateLimitStore.get(key) || { count: 0, expires: now + RATE_LIMIT_WINDOW };
  
  if (now > current.expires) {
    current.count = 1;
    current.expires = now + RATE_LIMIT_WINDOW;
  } else {
    current.count++;
  }
  
  rateLimitStore.set(key, current);
  
  // Different limits for different request types
  let maxRequests;
  switch (type) {
    case 'challenge':
      maxRequests = MAX_CHALLENGE_REQUESTS;
      break;
    case 'browsing':
      maxRequests = MAX_BROWSING_REQUESTS;
      break;
    case 'verify':
      maxRequests = MAX_REQUESTS_PER_WINDOW;
      break;
    default:
      maxRequests = MAX_REQUESTS_PER_WINDOW;
  }
  
  return current.count <= maxRequests;
}

// Security: Track failed authentication attempts
function trackFailedAttempt(identifier) {
  const now = Date.now();
  const key = `failed_${identifier}`;
  const current = failedAttempts.get(key) || { count: 0, expires: now + 15 * 60 * 1000 }; // 15 minute window
  
  if (now > current.expires) {
    current.count = 1;
    current.expires = now + 15 * 60 * 1000;
  } else {
    current.count++;
  }
  
  failedAttempts.set(key, current);
  return current.count;
}

// Security: Check if wallet is temporarily blocked due to too many failed attempts
function isWalletBlocked(identifier) {
  const key = `failed_${identifier}`;
  const data = failedAttempts.get(key);
  if (!data) return false;
  
  // Block after 5 failed attempts for 15 minutes
  return data.count >= 5 && Date.now() < data.expires;
}

// Security: Request validation (timestamp-based anti-replay)
function validateRequest(req) {
  const timestamp = req.headers['x-request-timestamp'];
  
  if (!timestamp) {
    return false;
  }
  
  // Check if timestamp is within 5 minutes
  const now = Date.now();
  const requestTime = parseInt(timestamp);
  if (Math.abs(now - requestTime) > 5 * 60 * 1000) {
    return false;
  }
  
  return true;
}

// Security: Improved session token generation
function generateSecureToken(walletAddress) {
  const timestamp = Date.now();
  const randomPart = Math.random().toString(36).substring(2) + Date.now().toString(36);
  const data = `${walletAddress}-${timestamp}-${randomPart}`;
  const hash = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('hex');
  return `${Buffer.from(data).toString('base64')}.${hash}`;
}

// Security: Generate browsing session token (shorter duration)
function generateBrowsingToken() {
  const timestamp = Date.now();
  const randomPart = Math.random().toString(36).substring(2) + Date.now().toString(36);
  const data = `browsing-${timestamp}-${randomPart}`;
  const hash = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('hex');
  return `browsing_${Buffer.from(data).toString('base64')}.${hash}`;
}

// Security: Validate wallet address format
function isValidWalletAddress(address) {
  try {
    new PublicKey(address);
    return true;
  } catch {
    return false;
  }
}

function generateChallenge() {
  return crypto.randomBytes(32).toString('hex');
}

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
  
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Request-Timestamp');
  
  // Security: Add security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://rpc.helius.xyz;");
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  
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
  
  // Handle session verification (GET request)
  if (req.method === 'GET') {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace('Bearer ', '');
    
    if (!token) {
      console.log(`[${requestId}] Session check failed: No token provided`);
      return res.status(401).json({
        success: false,
        valid: false,
        error: 'No session token provided'
      });
    }
    
    const session = activeSessions.get(token);
    if (session && Date.now() < session.expires) {
      console.log(`[${requestId}] Session valid for wallet: ${session.walletAddress.substring(0, 4)}...`);
      return res.status(200).json({
        success: true,
        valid: true,
        walletAddress: session.walletAddress.substring(0, 8) + '...',
        expires: session.expires,
        sessionType: session.type || 'authenticated'
      });
    } else {
      activeSessions.delete(token);
      console.log(`[${requestId}] Session invalid or expired`);
      return res.status(401).json({
        success: false,
        valid: false,
        error: 'Invalid or expired session'
      });
    }
  }
  
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  
  const { action, walletAddress, signature, challenge } = req.body;
  
  try {
    // Security: Validate request timestamp for POST requests
    if (req.method === 'POST' && !validateRequest(req)) {
      console.log(`[${requestId}] Invalid request timestamp`);
      return res.status(401).json({
        success: false,
        error: 'Invalid request timestamp'
      });
    }
    
    // Step 1: Generate challenge for wallet to sign
    if (action === 'challenge') {
      if (!walletAddress) {
        console.log(`[${requestId}] Challenge request missing wallet address`);
        return res.status(400).json({
          success: false,
          error: 'Wallet address is required'
        });
      }
      
      // Security: Validate wallet address format
      if (!isValidWalletAddress(walletAddress)) {
        console.log(`[${requestId}] Invalid wallet address format: ${walletAddress.substring(0, 8)}...`);
        return res.status(400).json({
          success: false,
          error: 'Invalid wallet address format'
        });
      }
      
      const cleanWalletAddress = walletAddress.trim();
      
      // Security: Check if wallet is temporarily blocked
      if (isWalletBlocked(cleanWalletAddress)) {
        console.log(`[${requestId}] Wallet temporarily blocked due to failed attempts: ${cleanWalletAddress.substring(0, 8)}...`);
        return res.status(429).json({
          success: false,
          error: 'Too many failed attempts. Please try again in 15 minutes.'
        });
      }
      
      // Security: Rate limiting per wallet
      if (!checkRateLimit(`wallet_${cleanWalletAddress}`, 'challenge')) {
        console.log(`[${requestId}] Rate limit exceeded for wallet: ${cleanWalletAddress.substring(0, 8)}...`);
        return res.status(429).json({
          success: false,
          error: 'Too many challenge requests for this wallet. Please try again later.'
        });
      }
      
      console.log(`[${requestId}] Challenge generated for wallet: ${cleanWalletAddress.substring(0, 4)}...`);
      
      const challengeCode = generateChallenge();
      const message = `Sign this message to verify wallet ownership and access The Mysterious Stranger game.\n\nChallenge: ${challengeCode}\nWallet: ${cleanWalletAddress}\nTimestamp: ${new Date().toISOString()}`;
      
      // Store challenge temporarily (expires in 5 minutes)
      pendingChallenges.set(challengeCode, {
        walletAddress: cleanWalletAddress,
        message,
        expires: Date.now() + 5 * 60 * 1000,
        requestId: requestId
      });
      
      return res.status(200).json({
        success: true,
        challenge: challengeCode,
        message: message
      });
    }
    
    // Step 1.5: Create browsing session (no wallet required)
    if (action === 'browsing') {
      console.log(`[${requestId}] Creating browsing session`);
      
      // Security: Rate limiting for browsing sessions
      if (!checkRateLimit(`browsing_${clientIP}`, 'browsing')) {
        console.log(`[${requestId}] Rate limit exceeded for browsing sessions`);
        return res.status(429).json({
          success: false,
          error: 'Too many browsing session requests. Please try again later.'
        });
      }
      
      // Generate browsing session token
      const browsingToken = generateBrowsingToken();
      const expires = Date.now() + BROWSING_SESSION_DURATION;
      
      // Store browsing session
      activeSessions.set(browsingToken, {
        walletAddress: 'browsing_user',
        expires,
        type: 'browsing',
        createdAt: Date.now()
      });
      
      console.log(`[${requestId}] Browsing session created, expires in ${BROWSING_SESSION_DURATION / (60 * 60 * 1000)} hours`);
      
      return res.status(200).json({
        success: true,
        sessionToken: browsingToken,
        expires,
        sessionType: 'browsing',
        message: 'Browsing session created. You can explore the game but will need to authenticate with a wallet to access the full adventure.'
      });
    }
    
    // Step 2: Verify signature and check NFT ownership
    if (action === 'verify') {
      if (!walletAddress || !signature || !challenge) {
        console.log(`[${requestId}] Verification request missing required fields`);
        return res.status(400).json({
          success: false,
          error: 'Wallet address, signature, and challenge are required'
        });
      }
      
      // Security: Validate wallet address format
      if (!isValidWalletAddress(walletAddress)) {
        console.log(`[${requestId}] Invalid wallet address in verification: ${walletAddress.substring(0, 8)}...`);
        return res.status(400).json({
          success: false,
          error: 'Invalid wallet address format'
        });
      }
      
      const cleanWalletAddress = walletAddress.trim();
      
      // Security: Check if wallet is temporarily blocked
      if (isWalletBlocked(cleanWalletAddress)) {
        console.log(`[${requestId}] Wallet temporarily blocked due to failed attempts: ${cleanWalletAddress.substring(0, 8)}...`);
        return res.status(429).json({
          success: false,
          error: 'Too many failed attempts. Please try again in 15 minutes.'
        });
      }
      
      // Security: Rate limiting for verification attempts
      if (!checkRateLimit(`wallet_${cleanWalletAddress}`, 'verify')) {
        console.log(`[${requestId}] Rate limit exceeded for wallet verification: ${cleanWalletAddress.substring(0, 8)}...`);
        return res.status(429).json({
          success: false,
          error: 'Too many verification attempts. Please try again later.'
        });
      }
      
      // Verify challenge exists and hasn't expired
      const challengeData = pendingChallenges.get(challenge);
      if (!challengeData) {
        console.log(`[${requestId}] Invalid or expired challenge`);
        trackFailedAttempt(cleanWalletAddress);
        return res.status(400).json({
          success: false,
          error: 'Invalid or expired challenge'
        });
      }
      
      if (challengeData.walletAddress !== cleanWalletAddress) {
        console.log(`[${requestId}] Wallet address mismatch in challenge`);
        trackFailedAttempt(cleanWalletAddress);
        return res.status(400).json({
          success: false,
          error: 'Wallet address mismatch'
        });
      }
      
      // Security: Verify challenge was created by this request or within reasonable time
      if (Math.abs(Date.now() - challengeData.expires + 5 * 60 * 1000) > 10 * 60 * 1000) {
        console.log(`[${requestId}] Challenge too old`);
        trackFailedAttempt(cleanWalletAddress);
        return res.status(400).json({
          success: false,
          error: 'Challenge too old'
        });
      }
      
      // Verify signature
      try {
        console.log(`[${requestId}] Verifying signature for wallet: ${cleanWalletAddress.substring(0, 4)}...`);
        const publicKey = new PublicKey(cleanWalletAddress);
        const messageBytes = new TextEncoder().encode(challengeData.message);
        
        // Handle different signature formats from Phantom wallet
        let signatureBytes;
        if (typeof signature === 'string') {
          // If signature is base58 encoded string
          try {
            signatureBytes = bs58.decode(signature);
          } catch {
            // If it's base64 encoded
            signatureBytes = Buffer.from(signature, 'base64');
          }
        } else if (signature instanceof Uint8Array) {
          signatureBytes = signature;
        } else if (Array.isArray(signature)) {
          signatureBytes = new Uint8Array(signature);
        } else {
          throw new Error('Unsupported signature format');
        }
        
        const isValid = nacl.sign.detached.verify(
          messageBytes,
          signatureBytes,
          publicKey.toBytes()
        );
        
        if (!isValid) {
          console.log(`[${requestId}] Invalid signature for wallet: ${cleanWalletAddress.substring(0, 4)}...`);
          trackFailedAttempt(cleanWalletAddress);
          return res.status(401).json({
            success: false,
            error: 'Invalid signature'
          });
        }
      } catch (error) {
        console.error(`[${requestId}] Signature verification error`);
        trackFailedAttempt(cleanWalletAddress);
        return res.status(401).json({
          success: false,
          error: 'Signature verification failed'
        });
      }
      
      // Clean up used challenge immediately after successful verification
      pendingChallenges.delete(challenge);
      
      // Security: Use proxy to check NFT ownership (hides Helius API key)
      try {
        console.log(`[${requestId}] Checking NFT ownership via proxy`);
        let hasRequiredNFT = false;
        for (const mintAddress of REQUIRED_NFT_ADDRESSES) {
          const proxyUrl = `${req.headers.host ? `https://${req.headers.host}` : 'http://localhost:3000'}/api/proxy-nft-query`;
          const proxyResponse = await fetch(proxyUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              walletAddress: cleanWalletAddress,
              nftMintAddress: mintAddress,
              sessionToken: 'temp'
            })
          });
          if (!proxyResponse.ok) {
            console.error(`[${requestId}] Proxy response not ok: ${proxyResponse.status} ${proxyResponse.statusText}`);
            continue;
          }
          const responseText = await proxyResponse.text();
          let proxyData;
          try {
            proxyData = JSON.parse(responseText);
          } catch (parseError) {
            console.error(`[${requestId}] Failed to parse proxy response:`, responseText.substring(0, 200));
            continue;
          }
          if (proxyData.success && proxyData.hasNFT) {
            hasRequiredNFT = true;
            break;
          }
        }
        if (hasRequiredNFT) {
          // Generate secure session token
          const sessionToken = generateSecureToken(cleanWalletAddress);
          const expires = Date.now() + AUTHENTICATED_SESSION_DURATION;
          // Store session
          activeSessions.set(sessionToken, {
            walletAddress: cleanWalletAddress,
            created: Date.now(),
            expires,
            verified: true,
            type: 'authenticated'
          });
          console.log(`[${requestId}] Wallet verified successfully: ${cleanWalletAddress.substring(0, 4)}...`);
          return res.status(200).json({
            success: true,
            message: 'Wallet verified and NFT ownership confirmed',
            sessionToken: sessionToken,
            expires: expires
          });
        } else {
          console.log(`[${requestId}] NFT not found for wallet: ${cleanWalletAddress.substring(0, 4)}...`);
          return res.status(403).json({
            success: false,
            error: 'Required NFT not found in wallet'
          });
        }
      } catch (error) {
        console.error(`[${requestId}] Proxy NFT verification error`);
        return res.status(500).json({
          success: false,
          error: 'Failed to verify NFT ownership'
        });
      }
    }
    
    console.log(`[${requestId}] Invalid action: ${action}`);
    return res.status(400).json({
      success: false,
      error: 'Invalid action'
    });
    
  } catch (error) {
    console.error(`[${requestId}] Verification error:`, error);
    return res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
}
