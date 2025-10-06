# cert-ctrl installation service deployment guide

This Cloudflare Worker provides a global installation service for cert-ctrl with intelligent routing, caching, and analytics.

## Features

- **Global Edge Distribution**: Serves installation scripts from 200+ Cloudflare locations
- **Intelligent Mirror Selection**: Automatically chooses best download source based on user location
- **GitHub Proxy**: Accelerates downloads and bypasses firewall restrictions
- **Platform Detection**: Customizes installation scripts based on user environment
- **Real-time Analytics**: Tracks installation patterns and success rates
- **Version Management**: Provides update checking and latest version resolution
- **Rate Limiting**: Protects against abuse while maintaining performance

## Quick Setup

### 1. Prerequisites

```bash
npm install -g wrangler
wrangler login
```

### 2. Configure Environment

```bash
# Copy and edit configuration
cp wrangler.toml.example wrangler.toml

# Set your GitHub repository details
wrangler secret put GITHUB_TOKEN  # Optional: for higher API limits
```

### 3. Create KV Namespaces

```bash
# Create KV namespaces
wrangler kv:namespace create RELEASE_CACHE
wrangler kv:namespace create ANALYTICS  
wrangler kv:namespace create CONFIG

# Update wrangler.toml with the returned namespace IDs
```

### 4. Deploy

```bash
npm install
npm run deploy
```

## URL Structure

Once deployed, your service will provide:

```
https://install.cjj365.cc/
├── /                           # Service information
├── /install.sh                 # Unix installation script
├── /install.ps1                # Windows PowerShell script
├── /api/version/latest         # Latest version info
├── /api/version/check          # Version comparison
├── /releases/proxy/{version}/  # Proxied GitHub releases
└── /health                     # Health check
```

## Usage Examples

### Quick Installation

```bash
# Unix/Linux/macOS
curl -fsSL https://install.cjj365.cc/install.sh | bash

# Windows PowerShell
iwr -useb https://install.cjj365.cc/install.ps1 | iex
```

### Advanced Installation

```bash
# User installation (no sudo)
curl -fsSL https://install.cjj365.cc/install.sh | bash -s -- --user-install

# Specific version
curl -fsSL https://install.cjj365.cc/install.sh | bash -s -- --version v1.2.3

# Verbose output
curl -fsSL https://install.cjj365.cc/install.sh | bash -s -- --verbose
```

### Version Checking

```bash
# Get latest version
curl https://install.cjj365.cc/api/version/latest

# Check if update available
curl "https://install.cjj365.cc/api/version/check?current=v1.0.0&platform=linux&arch=x64"
```

## Configuration

### Environment Variables

Set these in your Wrangler configuration:

```toml
[env.production.vars]
GITHUB_REPO_OWNER = "coderealm-atlas"
GITHUB_REPO_NAME = "cert-ctrl"
ANALYTICS_ENABLED = true
RATE_LIMIT_ENABLED = true
USE_PROXY_BY_DEFAULT = false
```

### Mirror Configuration

The service automatically selects mirrors based on user location:

- **Default**: Direct GitHub access
- **China**: Uses GitHub mirror (github.com.cnpmjs.org)
- **Corporate**: Falls back to Cloudflare proxy
- **Slow regions**: Automatic proxy activation

### Rate Limiting

Built-in rate limiting protects the service:

- **Per IP**: 100 requests per minute
- **Global**: 10,000 requests per minute  
- **Burst**: Allows temporary spikes

## Analytics

### Installation Tracking

The service tracks (anonymously):

- Installation counts by platform/region
- Version adoption rates
- Download success/failure rates
- Geographic distribution

### Querying Analytics

```bash
# Get daily installation stats
curl https://install.cert-ctrl.com/api/stats/daily

# Get platform breakdown
curl https://install.cert-ctrl.com/api/stats/platforms
```

## Development

### Local Development

```bash
# Install dependencies
npm install

# Start local development server
npm run dev

# Test installation script
curl http://localhost:8787/install.sh
```

### Testing

```bash
# Run tests
npm test

# Test with coverage
npm run test:coverage

# Type checking
npm run typecheck
```

### Code Structure

```
src/
├── index.js              # Main worker entry point
├── handlers/
│   ├── install.js         # Installation script generation
│   ├── version.js         # Version API endpoints
│   ├── proxy.js           # GitHub proxy functionality
│   ├── analytics.js       # Analytics endpoints
│   └── health.js          # Health check
├── utils/
│   ├── platform.js        # Platform/architecture detection
│   ├── cors.js            # CORS handling
│   ├── rateLimit.js       # Rate limiting logic
│   ├── analytics.js       # Analytics utilities
│   └── templates.js       # Template processing
└── templates/
    ├── install.sh.js       # Bash installation template
    └── install.ps1.js      # PowerShell installation template
```

## Monitoring

### Health Checks

The service provides health endpoints:

```bash
# Basic health check
curl https://install.cert-ctrl.com/health

# Response:
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2023-10-25T10:00:00Z",
  "cache_status": "ok",
  "github_api_status": "ok"
}
```

### Metrics

Key metrics to monitor:

- **Response time**: < 100ms p95
- **Success rate**: > 99.9%
- **Cache hit rate**: > 90%
- **GitHub API status**: Monitoring rate limits

### Alerts

Set up alerts for:

- High error rates (> 1%)
- Slow response times (> 500ms)
- GitHub API rate limit approaching
- Cache miss rate > 50%

## Security

### Rate Limiting

Multiple layers of protection:

```javascript
// Per-IP limits
const ipLimit = 100; // requests per minute

// Global limits  
const globalLimit = 10000; // requests per minute

// Burst allowance
const burstMultiplier = 2;
```

### Content Security

- **HTTPS Only**: All traffic encrypted
- **CORS Headers**: Controlled cross-origin access
- **Input Validation**: All parameters sanitized
- **No User Data**: Minimal logging for privacy

### GitHub Integration

- **Token Rotation**: Automatic token management
- **Signature Verification**: Validates release authenticity
- **Rate Limit Respect**: Stays within GitHub API limits

## Scaling

### Automatic Scaling

Cloudflare Workers automatically scale:

- **Requests**: Unlimited concurrent requests
- **Regions**: 200+ edge locations globally  
- **Latency**: < 50ms worldwide
- **Availability**: 99.99% SLA

### Cost Optimization

- **Free Tier**: 100K requests/day included
- **Caching**: Reduces GitHub API calls
- **KV Storage**: Cost-effective for analytics
- **Bandwidth**: Free for most usage

## Migration

### From Static Hosting

To migrate from static file hosting:

1. **Deploy Worker**: Set up Cloudflare Worker
2. **Update DNS**: Point install.cert-ctrl.com to Worker
3. **Test Installation**: Verify all platforms work
4. **Monitor**: Watch for any issues
5. **Cleanup**: Remove old static files

### Rollback Plan

If issues occur:

1. **DNS Switch**: Point back to static hosting
2. **Worker Disable**: Disable problematic routes
3. **Investigate**: Check logs and metrics
4. **Fix & Redeploy**: Address issues and redeploy

## Best Practices

### Performance

- **Cache Aggressively**: Use appropriate TTLs
- **Minimize API Calls**: Cache GitHub responses
- **Optimize Scripts**: Keep installation scripts lean
- **CDN Usage**: Leverage Cloudflare's global network

### Reliability

- **Error Handling**: Graceful degradation
- **Fallback Mirrors**: Multiple download sources
- **Health Monitoring**: Regular health checks
- **Gradual Rollouts**: Test changes incrementally

### Security

- **Minimal Logging**: Protect user privacy
- **Rate Limiting**: Prevent abuse
- **Input Validation**: Sanitize all inputs
- **HTTPS Everywhere**: Encrypt all traffic

## Support

### Troubleshooting

Common issues and solutions:

**Installation fails:**
- Check network connectivity
- Verify platform detection
- Try alternative mirror

**Slow downloads:**
- Use proxy endpoint
- Check regional mirror availability

**Version resolution fails:**
- Verify GitHub API access
- Check cache status

### Getting Help

- **Documentation**: This README and code comments
- **Issues**: GitHub repository issues
- **Monitoring**: Cloudflare dashboard and logs
- **Community**: Project discussions and forums