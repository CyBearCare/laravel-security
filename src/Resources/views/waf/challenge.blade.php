<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Challenge - Cybear Care</title>
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
            background: #f59e0b;
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

        .icon {
            width: 64px;
            height: 64px;
            margin: 0 auto 28px;
        }
        .icon svg {
            width: 100%;
            height: 100%;
        }

        .badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 0.78rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: #fcd34d;
            background: rgba(245, 158, 11, 0.1);
            border: 1px solid rgba(245, 158, 11, 0.2);
            padding: 4px 12px;
            border-radius: 20px;
            margin-bottom: 24px;
        }
        .badge-dot {
            width: 6px;
            height: 6px;
            background: #f59e0b;
            border-radius: 50%;
            animation: pulse-dot 2s ease-in-out infinite;
        }
        @keyframes pulse-dot {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
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

        /* Math challenge area */
        .math-box {
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 12px;
            padding: 28px 24px;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
        }
        .math-expression {
            font-size: 1.8rem;
            font-weight: 700;
            color: #fff;
            letter-spacing: 0.02em;
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
        }
        .math-input {
            width: 80px;
            padding: 12px;
            font-size: 1.4rem;
            font-weight: 600;
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
            text-align: center;
            background: rgba(255,255,255,0.05);
            border: 2px solid rgba(245, 158, 11, 0.3);
            border-radius: 10px;
            color: #fcd34d;
            outline: none;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .math-input:focus {
            border-color: #f59e0b;
            box-shadow: 0 0 0 3px rgba(245, 158, 11, 0.15);
        }
        .math-input::placeholder {
            color: #52525b;
        }

        /* Progress bar */
        .progress-track {
            width: 100%;
            height: 3px;
            background: rgba(255,255,255,0.06);
            border-radius: 2px;
            margin-bottom: 24px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #f59e0b, #f97316);
            width: 0%;
            border-radius: 2px;
            animation: progress 30s linear forwards;
        }
        @keyframes progress {
            to { width: 100%; }
        }

        /* Submit button */
        .submit-btn {
            width: 100%;
            padding: 14px 24px;
            font-size: 0.925rem;
            font-weight: 600;
            color: #18181b;
            background: linear-gradient(135deg, #fcd34d, #f59e0b);
            border: none;
            border-radius: 10px;
            cursor: pointer;
            transition: transform 0.15s, box-shadow 0.15s;
            letter-spacing: 0.01em;
        }
        .submit-btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 8px 24px rgba(245, 158, 11, 0.25);
        }
        .submit-btn:active {
            transform: translateY(0);
        }

        /* Footer */
        .footer {
            margin-top: 28px;
            padding-top: 20px;
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
            margin-top: 10px;
            font-size: 0.78rem;
            font-weight: 600;
            color: #71717a;
        }
        .footer .brand svg {
            width: 14px;
            height: 14px;
            opacity: 0.6;
        }

        @media (max-width: 520px) {
            .card { padding: 36px 24px 28px; }
            h1 { font-size: 1.4rem; }
            .math-expression { font-size: 1.4rem; }
            .math-input { width: 70px; font-size: 1.2rem; }
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">
            <svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M32 4L8 16v16c0 14.4 10.24 27.84 24 32 13.76-4.16 24-17.6 24-32V16L32 4z" fill="rgba(245,158,11,0.1)" stroke="#f59e0b" stroke-width="2.5" stroke-linejoin="round"/>
                <circle cx="32" cy="28" r="4" fill="#f59e0b"/>
                <path d="M32 36v6" stroke="#f59e0b" stroke-width="2.5" stroke-linecap="round"/>
            </svg>
        </div>

        <div class="badge">
            <span class="badge-dot"></span>
            Verification Required
        </div>

        <h1>Security Challenge</h1>
        <p class="subtitle">Complete this verification before continuing.</p>

        <form method="GET" class="challenge-form" id="challengeForm">
            <div class="math-box">
                <span class="math-expression">{{ $challenge_left }} + {{ $challenge_right }} =</span>
                <input type="text" name="cybear_challenge_answer" class="math-input" id="mathInput"
                       aria-label="Security challenge answer" required inputmode="numeric" pattern="[0-9]+"
                       autocomplete="off" autofocus placeholder="?">
            </div>

            <input type="hidden" name="cybear_challenge_token" value="{{ $challenge_token }}">

            <div class="progress-track">
                <div class="progress-fill"></div>
            </div>

            <button type="submit" class="submit-btn">Verify &amp; Continue</button>
        </form>

        <div class="footer">
            <p>This challenge protects the site from automated attacks.</p>
            <span class="brand">
                <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 1.2a5.8 5.8 0 110 11.6A5.8 5.8 0 018 2.2zm-.5 3a.8.8 0 011.6 0v3.3a.8.8 0 01-1.6 0V5.2zm.8 6.1a.9.9 0 100-1.8.9.9 0 000 1.8z"/></svg>
                Protected by Cybear Care
            </span>
        </div>
    </div>

    <noscript><meta http-equiv="refresh" content="30"></noscript>
</body>
</html>
