# Cybear Laravel Security Package - Installation Guide

> **Complete setup guide for integrating Cybear security monitoring and protection into your Laravel application**

## 📋 Requirements

- **PHP**: 8.1 or higher
- **Laravel**: 10.0 or higher  
- **Database**: MySQL 5.7+, PostgreSQL 12+, or SQLite 3.8+
- **Cache**: Redis recommended (for optimal performance)
- **Cybear Account**: Active API key from [Cybear Platform](https://cybear.care)

## 🚀 Installation Steps

### Step 1: Install via Composer

```bash
composer require cybear-care/laravel-security
```

### Step 2: Run the Interactive Setup

The package includes an interactive setup command that handles most configuration automatically:

```bash
php artisan cybear:setup
```

This command will:
- ✅ Prompt for your Cybear API key
- ✅ Update your `.env` file with configuration
- ✅ Publish configuration files
- ✅ Run database migrations
- ✅ Sync initial WAF rules from Cybear platform
- ✅ Test API connectivity

**That's it!** The package is now installed and active.

---

## 🔧 Manual Configuration (Optional)

If you prefer manual setup or need custom configuration:

### 1. Publish Configuration Files

```bash
php artisan vendor:publish --tag=cybear-config
```

### 2. Add Environment Variables

Add these variables to your `.env` file:

```env
# Required - Get from your Cybear dashboard
CYBEAR_API_KEY=your_api_key_here
CYBEAR_API_ENDPOINT=https://api.cybear.care

# WAF Configuration (Optional)
CYBEAR_WAF_ENABLED=true
CYBEAR_WAF_MODE=monitor  # or 'enforce' for blocking

# Audit Logging (Optional) 
CYBEAR_AUDIT_ENABLED=true
CYBEAR_AUDIT_LOG_REQUESTS=true
CYBEAR_AUDIT_RETENTION_DAYS=90

# Data Collection (Optional)
CYBEAR_COLLECTORS_AUTO_SCHEDULE=true
CYBEAR_COLLECTORS_INTERVAL=hourly

# Rate Limiting (Optional)
CYBEAR_RATE_LIMIT_ENABLED=true
CYBEAR_RATE_LIMIT_RPM=60
CYBEAR_RATE_LIMIT_RPH=1000
```

### 3. Run Database Migrations

```bash
php artisan migrate
```

### 4. Sync WAF Rules

```bash
php artisan cybear:sync
```

---

## ✅ What Happens Automatically

### 🛡️ **WAF Protection** (Immediate)
- **Auto-enabled** on all `web` and `api` routes
- **Real-time protection** against common attacks (SQL injection, XSS, etc.)
- **Configurable modes**: `monitor` (log only) or `enforce` (block threats)
- **No code changes required**

### 📊 **Audit Logging** (Immediate)  
- **Auto-enabled** on all `web` and `api` routes
- **Comprehensive logging** of requests, security events, and authentication
- **Automatic data sanitization** to protect sensitive information
- **No code changes required**

### 🔄 **Data Collection** (Scheduled)
- **Hourly collection** of security and application data
- **Automatic transmission** to Cybear platform
- **9 different collectors**: packages, environment, security, auth, database, filesystem, network, application, performance
- **Configurable via environment variables**

### ⚡ **Rate Limiting** (Optional)
- **Intelligent rate limiting** with multiple time windows
- **IP and user-based tracking**
- **Configurable limits** per minute/hour/day

---

## 🎛️ Available Commands

### Core Commands
```bash
# Check system status and health
php artisan cybear:status

# Manual data collection and transmission  
php artisan cybear:collect

# Sync latest WAF rules from platform
php artisan cybear:sync

# Test API connectivity
php artisan cybear:test
```

### Advanced Usage
```bash
# Collect specific data type
php artisan cybear:collect --type=packages
php artisan cybear:collect --type=security

# Collect and send immediately
php artisan cybear:collect --send

# Force rule sync (bypass cache)
php artisan cybear:sync --force

# Detailed system status
php artisan cybear:status --detailed
```

---

## 🔧 Configuration Options

### WAF Configuration

```php
// config/cybear.php
'waf' => [
    'enabled' => true,           // Enable/disable WAF
    'mode' => 'monitor',         // 'monitor' or 'enforce'
    'cache_rules' => true,       // Cache rules for performance
    'cache_ttl' => 3600,        // Cache time in seconds
    'challenge_enabled' => false, // Enable CAPTCHA challenges
],
```

### Audit Logging Configuration

```php
'audit' => [
    'enabled' => true,
    'log_requests' => true,      // Log HTTP requests
    'log_responses' => false,    // Log HTTP responses
    'log_authentication' => true, // Log auth events
    'excluded_routes' => [       // Skip logging for these routes
        'telescope*',
        'horizon*',
        '_debugbar*',
    ],
    'retention_days' => 90,      // Auto-cleanup after 90 days
],
```

### Data Collection Configuration

```php
'collectors' => [
    'auto_schedule' => true,     // Auto-schedule collection
    'collection_interval' => 'hourly', // hourly, daily, weekly
    
    // Individual collector settings
    'packages' => ['enabled' => true],
    'security' => ['enabled' => true],
    'environment' => ['enabled' => true],
    'auth' => ['enabled' => true],
    'database' => ['enabled' => true],
    'filesystem' => ['enabled' => true],
    'network' => ['enabled' => true],
    'application' => ['enabled' => true],
    'performance' => ['enabled' => true],
],
```

---

## 🎯 Middleware Usage (Optional)

While middleware is auto-registered, you can also use it manually:

### Route-Specific Protection
```php
// Apply to specific routes
Route::middleware(['cybear.waf'])->group(function () {
    Route::get('/admin', [AdminController::class, 'index']);
});

// Apply audit logging only
Route::middleware(['cybear.audit'])->group(function () {
    Route::post('/api/sensitive', [ApiController::class, 'sensitive']);
});

// Apply rate limiting
Route::middleware(['cybear.ratelimit'])->group(function () {
    Route::post('/api/public', [ApiController::class, 'public']);
});
```

### Custom Middleware Groups
```php
// app/Http/Kernel.php
protected $middlewareGroups = [
    'api' => [
        // ... existing middleware
        'cybear.waf',      // Already auto-registered
        'cybear.audit',    // Already auto-registered
        'cybear.ratelimit',
    ],
];
```

---

## 🔍 Verification & Testing

### 1. Check Installation Status
```bash
php artisan cybear:status
```

Expected output:
```
🔍 Cybear Security Status

✅ Configuration: Valid
✅ API Connection: Connected (response: 45ms)
✅ WAF Status: Active (monitor mode)
✅ Audit Logging: Active
✅ Data Collection: Scheduled (hourly)

📊 Last 24 Hours:
- Total Requests: 1,247
- Blocked Requests: 0
- Security Events: 3
- Data Collections: 24
```

### 2. Test WAF Protection
```bash
# This should trigger WAF detection
curl "https://your-app.com/test?id=1' OR '1'='1"
```

### 3. Verify Data Collection
```bash
php artisan cybear:collect --type=packages
```

### 4. Check Database Tables
```bash
php artisan tinker
```
```php
// Check if tables exist
DB::table('cybear_audit_logs')->count();
DB::table('cybear_waf_rules')->count();
DB::table('cybear_collected_data')->count();
```

---

## 🚨 Troubleshooting

### API Connection Issues
```bash
# Test API connectivity
php artisan cybear:test

# Check configuration
php artisan config:show cybear
```

### WAF Not Blocking Threats
1. Check WAF mode: `CYBEAR_WAF_MODE=enforce` in `.env`
2. Verify rules are synced: `php artisan cybear:sync`
3. Check logs: `tail -f storage/logs/laravel.log`

### Data Collection Not Working
1. Verify scheduler is running: `php artisan schedule:list`
2. Run manual collection: `php artisan cybear:collect`
3. Check collector configuration in `config/cybear.php`

### Performance Issues
1. Enable Redis caching for WAF rules
2. Adjust collection interval: `CYBEAR_COLLECTORS_INTERVAL=daily`
3. Exclude static assets from audit logging

### Migration Errors
```bash
# If migrations fail, run individually
php artisan migrate --path=/vendor/cybear-care/laravel-security/src/Database/Migrations
```

---

## 🔄 Updating

### Update Package
```bash
composer update cybear-care/laravel-security
```

### Sync New Features
```bash
php artisan cybear:sync
php artisan vendor:publish --tag=cybear-config --force
```

---

## 🎯 Production Deployment

### Performance Optimization
```env
# Use Redis for caching
CACHE_DRIVER=redis
CYBEAR_WAF_CACHE_RULES=true
CYBEAR_RATE_LIMIT_CACHE=redis

# Optimize collection interval
CYBEAR_COLLECTORS_INTERVAL=daily
```

### Security Hardening
```env
# Enable enforcement mode
CYBEAR_WAF_MODE=enforce

# Enable all audit logging
CYBEAR_AUDIT_LOG_REQUESTS=true
CYBEAR_AUDIT_LOG_AUTH=true

# Strict rate limiting
CYBEAR_RATE_LIMIT_RPM=30
CYBEAR_RATE_LIMIT_RPH=500
```

### Monitoring
- Monitor logs: `tail -f storage/logs/laravel.log | grep Cybear`
- Check status: `php artisan cybear:status`
- View dashboard: [Cybear Platform](https://cybear.care/dashboard)


## 🔐 Security Notice

This package automatically protects your application, but remember:
- Keep your Cybear API key secure
- Regularly update the package for latest security patches
- Monitor the Cybear dashboard for security alerts
- Review audit logs for suspicious activity

**Your Laravel application is now secured by Cybear! 🐻🛡️**