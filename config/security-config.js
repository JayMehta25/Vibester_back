/**
 * Security Configuration
 * Centralized security settings for rate limiting, CORS, and validation
 * OWASP Best Practices Implementation
 */

// ==========================================
// RATE LIMITING CONFIGURATIONS
// ==========================================

/**
 * Global rate limiter - applies to all requests
 * Prevents DoS attacks by limiting requests per IP
 */
export const globalRateLimitConfig = {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    // Skip successful requests from counting against the limit
    skipSuccessfulRequests: false,
    // Skip failed requests from counting against the limit
    skipFailedRequests: false,
};

/**
 * Authentication endpoints rate limiter
 * Stricter limits to prevent brute force attacks
 */
export const authRateLimitConfig = {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: 'Too many authentication attempts, please try again after 15 minutes.',
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false,
    skipFailedRequests: false,
};

/**
 * AI endpoints rate limiter
 * Moderate limits to prevent API quota exhaustion
 */
export const aiRateLimitConfig = {
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20, // Limit each IP to 20 requests per 5 minutes
    message: 'Too many AI requests, please try again in a few minutes.',
    standardHeaders: true,
    legacyHeaders: false,
};

/**
 * File upload rate limiter
 * Strict limits to prevent storage abuse
 */
export const uploadRateLimitConfig = {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10, // Limit each IP to 10 uploads per hour
    message: 'Too many file uploads, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
};

/**
 * Password reset rate limiter
 * Very strict to prevent abuse
 */
export const passwordResetRateLimitConfig = {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // Limit each IP to 3 requests per hour
    message: 'Too many password reset requests, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
};

// ==========================================
// CORS CONFIGURATION
// ==========================================

/**
 * Allowed origins for CORS
 * Add your production domains here
 */
export const allowedOrigins = [
    'http://localhost:3000',
    'http://localhost:5173',
    'https://vibester.me',
    'http://vibester.me',
    'https://www.vibester.me',
    'http://www.vibester.me',
];

/**
 * CORS origin validator
 * Allows localhost and ngrok URLs for development
 */
export const corsOriginValidator = (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) {
        return callback(null, true);
    }

    // Check if origin is in allowed list
    if (allowedOrigins.includes(origin)) {
        return callback(null, true);
    }

    // Allow ngrok URLs for development/testing
    if (origin.includes('ngrok-free.app') || origin.includes('ngrok.io')) {
        return callback(null, true);
    }

    // Allow production domains
    if (origin.includes('vibester.me') ||
        origin.includes('vercel.app') ||
        origin.includes('onrender.com')) {
        return callback(null, true);
    }

    // Reject all other origins
    callback(new Error('Not allowed by CORS'));
};

// ==========================================
// INPUT VALIDATION CONSTANTS
// ==========================================

/**
 * Username validation rules
 */
export const USERNAME_RULES = {
    minLength: 3,
    maxLength: 30,
    pattern: /^[a-zA-Z0-9_-]+$/, // Alphanumeric, underscore, hyphen only
    errorMessage: 'Username must be 3-30 characters and contain only letters, numbers, underscores, and hyphens',
};

/**
 * Password validation rules
 * OWASP recommendations for password strength
 */
export const PASSWORD_RULES = {
    minLength: 8,
    maxLength: 128,
    errorMessage: 'Password must be at least 8 characters long',
};

/**
 * Email validation rules
 */
export const EMAIL_RULES = {
    pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    errorMessage: 'Please provide a valid email address',
};

/**
 * OTP validation rules
 */
export const OTP_RULES = {
    length: 6,
    pattern: /^\d{6}$/,
    errorMessage: 'OTP must be a 6-digit number',
};

/**
 * Room code validation rules
 */
export const ROOM_CODE_RULES = {
    length: 6,
    pattern: /^[a-z0-9]{6}$/,
    errorMessage: 'Room code must be 6 alphanumeric characters',
};

/**
 * Message content validation rules
 */
export const MESSAGE_RULES = {
    maxLength: 5000,
    errorMessage: 'Message cannot exceed 5000 characters',
};

/**
 * Interest validation rules
 */
export const INTEREST_RULES = {
    minLength: 2,
    maxLength: 50,
    maxCount: 10,
    pattern: /^[a-zA-Z0-9\s-]+$/,
    errorMessage: 'Each interest must be 2-50 characters and contain only letters, numbers, spaces, and hyphens',
};

/**
 * File upload validation rules
 */
export const FILE_UPLOAD_RULES = {
    maxSize: 10 * 1024 * 1024, // 10MB
    allowedImageTypes: ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml'],
    allowedVideoTypes: ['video/mp4', 'video/webm', 'video/quicktime'],
    allowedAudioTypes: ['audio/mpeg', 'audio/mp3', 'audio/mp4', 'audio/ogg', 'audio/wav', 'audio/webm'],
    allowedDocumentTypes: ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'text/plain'],
};

// ==========================================
// SECURITY HEADERS CONFIGURATION
// ==========================================

/**
 * Helmet.js configuration for security headers
 * OWASP recommended security headers
 */
export const helmetConfig = {
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", 'data:', 'https:'],
            connectSrc: ["'self'", 'ws:', 'wss:'],
            fontSrc: ["'self'", 'data:'],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true,
    },
    frameguard: {
        action: 'deny',
    },
    noSniff: true,
    xssFilter: true,
};

// ==========================================
// ENVIRONMENT VALIDATION
// ==========================================

/**
 * Required environment variables
 * Server will not start if these are missing
 */
export const REQUIRED_ENV_VARS = [
    'GEMINI_API_KEY',
    'JWT_SECRET',
    'EMAIL_USER',
    'EMAIL_PASS',
];

/**
 * Validate that all required environment variables are present
 * @throws {Error} If any required environment variable is missing
 */
export function validateEnvironment() {
    const missing = [];

    for (const varName of REQUIRED_ENV_VARS) {
        if (!process.env[varName]) {
            missing.push(varName);
        }
    }

    if (missing.length > 0) {
        throw new Error(
            `❌ SECURITY ERROR: Missing required environment variables:\n` +
            missing.map(v => `  - ${v}`).join('\n') +
            `\n\nPlease check your .env file and ensure all required variables are set.`
        );
    }

    console.log('✅ All required environment variables are present');
}
