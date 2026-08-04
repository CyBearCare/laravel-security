<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Blocked - Cybear Care</title>
    <style>
        *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', Roboto, sans-serif;
            background: #0f0f13;
            color: #e4e4e7;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 24px;
            overflow: hidden;
        }

        /* Subtle animated gradient orbs */
        body::before, body::after {
            content: '';
            position: fixed;
            border-radius: 50%;
            filter: blur(120px);
            opacity: 0.15;
            z-index: 0;
            animation: drift 20s ease-in-out infinite alternate;
        }
        body::before {
            width: 600px; height: 600px;
            background: #ef4444;
            top: -200px; left: -100px;
        }
        body::after {
            width: 500px; height: 500px;
            background: #f97316;
            bottom: -200px; right: -100px;
            animation-delay: -10s;
        }
        @keyframes drift {
            0%   { transform: translate(0, 0) scale(1); }
            100% { transform: translate(60px, 40px) scale(1.1); }
        }

        .card {
            position: relative;
            z-index: 1;
            width: 100%;
            max-width: 480px;
            background: rgba(24, 24, 30, 0.85);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 20px;
            padding: 48px 40px 40px;
            text-align: center;
        }

        /* Shield icon */
        .icon {
            width: 64px;
            height: 64px;
            margin: 0 auto 28px;
            position: relative;
        }
        .icon svg {
            width: 100%;
            height: 100%;
        }

        h1 {
            font-size: 1.65rem;
            font-weight: 700;
            color: #fff;
            letter-spacing: -0.02em;
            margin-bottom: 8px;
        }
        .subtitle {
            font-size: 0.925rem;
            color: #a1a1aa;
            line-height: 1.5;
            margin-bottom: 32px;
        }

        /* Details panel */
        .details {
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 12px;
            padding: 20px 24px;
            text-align: left;
        }
        .detail-row {
            display: flex;
            justify-content: space-between;
            align-items: baseline;
            padding: 10px 0;
        }
        .detail-row + .detail-row {
            border-top: 1px solid rgba(255,255,255,0.05);
        }
        .detail-label {
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #71717a;
            flex-shrink: 0;
            margin-right: 16px;
        }
        .detail-value {
            font-size: 0.875rem;
            color: #d4d4d8;
            text-align: right;
            word-break: break-all;
        }
        .incident-id {
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
            font-size: 0.82rem;
            letter-spacing: 0.04em;
            background: rgba(239, 68, 68, 0.08);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.15);
            padding: 8px 14px;
            border-radius: 8px;
            display: block;
            text-align: center;
            margin-top: 4px;
            user-select: all;
            cursor: pointer;
        }
        .incident-id:hover {
            background: rgba(239, 68, 68, 0.12);
            border-color: rgba(239, 68, 68, 0.25);
        }

        /* Status badge */
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 0.78rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: #fca5a5;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.2);
            padding: 4px 12px;
            border-radius: 20px;
            margin-bottom: 24px;
        }
        .badge-dot {
            width: 6px;
            height: 6px;
            background: #ef4444;
            border-radius: 50%;
            animation: pulse-dot 2s ease-in-out infinite;
        }
        @keyframes pulse-dot {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
        }

        /* Footer */
        .footer {
            margin-top: 32px;
            padding-top: 24px;
            border-top: 1px solid rgba(255,255,255,0.05);
        }
        .footer p {
            font-size: 0.8rem;
            color: #52525b;
            line-height: 1.6;
        }
        .footer .brand {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            margin-top: 12px;
            font-size: 0.78rem;
            font-weight: 600;
            color: #71717a;
            text-decoration: none;
        }
        .footer .brand svg {
            width: 14px;
            height: 14px;
            opacity: 0.6;
        }

        @media (max-width: 520px) {
            .card { padding: 36px 24px 28px; }
            h1 { font-size: 1.4rem; }
            .detail-row { flex-direction: column; gap: 4px; }
            .detail-value { text-align: left; }
        }
    </style>
</head>
<body>
    <div class="card">
        <!-- Shield icon as inline SVG -->
        <div class="icon">
            <svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M32 4L8 16v16c0 14.4 10.24 27.84 24 32 13.76-4.16 24-17.6 24-32V16L32 4z" fill="rgba(239,68,68,0.1)" stroke="#ef4444" stroke-width="2.5" stroke-linejoin="round"/>
                <path d="M24 32l6 6 12-12" stroke="#ef4444" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" opacity="0"/>
                <path d="M22 22l20 20M42 22L22 42" stroke="#ef4444" stroke-width="2.5" stroke-linecap="round"/>
            </svg>
        </div>

        <div class="badge">
            <span class="badge-dot"></span>
            Request Blocked
        </div>

        <h1>Access Denied</h1>
        <p class="subtitle">This request was blocked by the web application firewall. If you believe this is a mistake, contact the site administrator.</p>

        <div class="details">
            <div class="detail-row">
                <span class="detail-label">Reason</span>
                <span class="detail-value">
                    @if(config('app.debug'))
                        {{ $analysis['block_reason'] ?? 'Security rule violation' }}
                    @else
                        Security rule violation
                    @endif
                </span>
            </div>
            @if(isset($analysis['rule_id']) && config('app.debug'))
            <div class="detail-row">
                <span class="detail-label">Rule</span>
                <span class="detail-value">{{ $analysis['rule_id'] }}</span>
            </div>
            @endif
            <div class="detail-row">
                <span class="detail-label">Time</span>
                <span class="detail-value">{{ now()->format('Y-m-d H:i:s') }} UTC</span>
            </div>
            <div class="detail-row" style="flex-direction:column;align-items:center;gap:6px">
                <span class="detail-label" style="margin-right:0">Incident ID</span>
                <span class="incident-id">{{ $analysis['incident_id'] ?? Str::uuid() }}</span>
            </div>
        </div>

        <div class="footer">
            <p>Quote the incident ID when contacting support.</p>
            <span class="brand">
                <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 1.2a5.8 5.8 0 110 11.6A5.8 5.8 0 018 2.2zm-.5 3a.8.8 0 011.6 0v3.3a.8.8 0 01-1.6 0V5.2zm.8 6.1a.9.9 0 100-1.8.9.9 0 000 1.8z"/></svg>
                Protected by Cybear Care
            </span>
        </div>
    </div>
</body>
</html>
