<!doctype html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <meta name="robots" content="noindex, nofollow, noarchive">
    <title>This request was stopped: {{ config('app.name', 'Application') }}</title>
    <style>
        :root {
            color-scheme: dark;
            --cybear-ink: #08111f;
            --cybear-ink-raised: #0c1729;
            --cybear-blue: #2d6df6;
            --cybear-blue-hover: #245fdc;
            --cybear-blue-light: #76a7ff;
            --cybear-text: #f0f5ff;
            --cybear-text-muted: #9aa8be;
            --cybear-border: #263750;
            --cybear-focus: #8cb6ff;
            --cybear-ease-out: cubic-bezier(0.22, 1, 0.36, 1);
        }

        *,
        *::before,
        *::after {
            box-sizing: border-box;
        }

        html {
            min-height: 100%;
            background: var(--cybear-ink);
        }

        body {
            min-width: 17.5rem;
            min-height: 100vh;
            min-height: 100dvh;
            margin: 0;
            color: var(--cybear-text);
            background:
                linear-gradient(rgba(122, 151, 207, 0.052) 1px, transparent 1px),
                linear-gradient(90deg, rgba(122, 151, 207, 0.052) 1px, transparent 1px),
                var(--cybear-ink);
            background-size: 4rem 4rem;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            font-size: 1rem;
            font-kerning: normal;
            line-height: 1.6;
        }

        body::before {
            position: fixed;
            z-index: 0;
            inset-block-start: -28rem;
            inset-inline-end: -14rem;
            width: 56rem;
            height: 56rem;
            border-radius: 50%;
            background: rgba(45, 109, 246, 0.2);
            content: "";
            filter: blur(8rem);
            pointer-events: none;
        }

        a {
            color: inherit;
        }

        .cybear-skip-link {
            position: fixed;
            z-index: 5;
            inset-block-start: 0.75rem;
            inset-inline-start: 0.75rem;
            padding: 0.65rem 0.9rem;
            border-radius: 0.35rem;
            color: var(--cybear-ink);
            background: var(--cybear-text);
            font-size: 0.875rem;
            font-weight: 700;
            text-decoration: none;
            transform: translateY(-180%);
            transition: transform 180ms var(--cybear-ease-out);
        }

        .cybear-skip-link:focus {
            transform: translateY(0);
        }

        .cybear-response-shell {
            position: relative;
            z-index: 1;
            display: grid;
            width: min(100%, 72rem);
            min-height: 100vh;
            min-height: 100dvh;
            margin-inline: auto;
            padding:
                max(1.25rem, env(safe-area-inset-top))
                max(1.25rem, env(safe-area-inset-right))
                max(1.25rem, env(safe-area-inset-bottom))
                max(1.25rem, env(safe-area-inset-left));
            grid-template-rows: auto 1fr auto;
        }

        .cybear-response-brand {
            display: inline-flex;
            width: fit-content;
            min-height: 3rem;
            align-items: center;
            gap: 0.75rem;
            color: #eef3ff;
            font-size: 1.0625rem;
            font-weight: 700;
            letter-spacing: -0.035em;
            text-decoration: none;
        }

        .cybear-response-brand-mark {
            display: flex;
            width: 2.75rem;
            height: 3rem;
            align-items: center;
            justify-content: center;
        }

        .cybear-response-brand-mark svg {
            display: block;
            width: 2.55rem;
            height: 3rem;
        }

        .cybear-response-brand-name span {
            color: var(--cybear-blue-light);
        }

        .cybear-response-main {
            display: grid;
            align-items: center;
            gap: 3rem;
            padding-block: clamp(4rem, 12vh, 8rem);
        }

        .cybear-response-copy {
            max-width: 43rem;
            animation: cybear-response-enter 620ms var(--cybear-ease-out) both;
        }

        .cybear-response-eyebrow {
            margin: 0;
            color: var(--cybear-blue-light);
            font-size: 0.75rem;
            font-weight: 750;
            letter-spacing: 0.12em;
            line-height: 1.4;
            text-transform: uppercase;
        }

        .cybear-response-title {
            max-width: 12ch;
            margin: 1rem 0 0;
            color: var(--cybear-text);
            font-size: clamp(2.5rem, 8vw, 5.25rem);
            font-weight: 620;
            letter-spacing: -0.06em;
            line-height: 0.98;
            overflow-wrap: break-word;
            text-wrap: balance;
        }

        .cybear-response-message {
            max-width: 39rem;
            margin: 1.5rem 0 0;
            color: var(--cybear-text-muted);
            font-size: 1rem;
            line-height: 1.75;
            text-wrap: pretty;
        }

        .cybear-response-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 0.75rem;
            margin-block-start: 2rem;
        }

        .cybear-response-action {
            display: inline-flex;
            min-height: 3rem;
            align-items: center;
            justify-content: center;
            padding: 0.75rem 1.1rem;
            border: 1px solid var(--cybear-border);
            border-radius: 0.375rem;
            color: #dce6f7;
            background: var(--cybear-ink-raised);
            font-size: 0.875rem;
            font-weight: 700;
            line-height: 1.2;
            text-decoration: none;
            transition:
                background-color 160ms var(--cybear-ease-out),
                border-color 160ms var(--cybear-ease-out),
                color 160ms var(--cybear-ease-out),
                transform 160ms var(--cybear-ease-out);
        }

        .cybear-response-status {
            display: grid;
            max-width: 26rem;
            gap: 1.25rem;
            padding-block: 1.5rem;
            border-block: 1px solid var(--cybear-border);
            animation: cybear-response-enter 620ms 80ms var(--cybear-ease-out) both;
        }

        .cybear-response-status-heading {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .cybear-response-status-marker {
            position: relative;
            display: block;
            width: 0.625rem;
            height: 0.625rem;
            flex: 0 0 auto;
            border-radius: 50%;
            background: var(--cybear-blue-light);
        }

        .cybear-response-status-marker::after {
            position: absolute;
            inset: -0.375rem;
            border: 1px solid rgba(118, 167, 255, 0.3);
            border-radius: inherit;
            content: "";
        }

        .cybear-response-status strong {
            color: #e7eefb;
            font-size: 0.875rem;
            font-weight: 700;
        }

        .cybear-response-status dl {
            display: grid;
            margin: 0;
            gap: 0.75rem;
        }

        .cybear-response-status dl div {
            display: flex;
            min-width: 0;
            justify-content: space-between;
            gap: 1.5rem;
        }

        .cybear-response-status dt,
        .cybear-response-status dd {
            margin: 0;
            font-size: 0.75rem;
            line-height: 1.5;
        }

        .cybear-response-status dt {
            color: #7888a0;
        }

        .cybear-response-status dd {
            max-width: 15rem;
            color: #c8d4e6;
            font-weight: 650;
            text-align: end;
            overflow-wrap: anywhere;
        }

        .cybear-response-reference {
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
            font-variant-numeric: tabular-nums;
            user-select: all;
        }

        .cybear-response-footer {
            display: flex;
            min-height: 3rem;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
            padding-block-start: 1rem;
            border-block-start: 1px solid rgba(149, 174, 219, 0.14);
            color: #718198;
            font-size: 0.75rem;
        }

        .cybear-response-code {
            color: #96a5bb;
            font-variant-numeric: tabular-nums;
            font-weight: 700;
            letter-spacing: 0.08em;
        }

        @media (hover: hover) {
            .cybear-response-action:hover {
                color: #f0f5ff;
                border-color: #3a5274;
                background: #11223b;
                transform: translateY(-1px);
            }
        }

        .cybear-response-action:active {
            transform: translateY(0);
        }

        .cybear-response-brand:focus-visible,
        .cybear-response-action:focus-visible {
            outline: 2px solid var(--cybear-focus);
            outline-offset: 3px;
        }

        @media (min-width: 48rem) {
            .cybear-response-shell {
                padding-inline: clamp(2rem, 6vw, 5rem);
            }

            .cybear-response-main {
                grid-template-columns: minmax(0, 1.7fr) minmax(16rem, 0.8fr);
                gap: clamp(4rem, 10vw, 8rem);
            }

            .cybear-response-status {
                justify-self: end;
            }
        }

        @media (max-width: 30rem) {
            .cybear-response-footer {
                align-items: flex-start;
                flex-direction: column;
                justify-content: flex-start;
            }

            .cybear-response-status dl div {
                align-items: flex-start;
                flex-direction: column;
                gap: 0.15rem;
            }

            .cybear-response-status dd {
                max-width: 100%;
                text-align: start;
            }
        }

        @media (prefers-reduced-motion: reduce) {
            *,
            *::before,
            *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }
        }

        @keyframes cybear-response-enter {
            from {
                opacity: 0;
                transform: translateY(0.75rem);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
    </style>
</head>
<body>
    <a class="cybear-skip-link" href="#cybear-response-content">Skip to response</a>

    <div class="cybear-response-shell">
        <header>
            <a class="cybear-response-brand" href="/" aria-label="Return to {{ config('app.name', 'application') }}">
                <span class="cybear-response-brand-mark" aria-hidden="true">
                    <svg viewBox="0 0 354 416" xmlns="http://www.w3.org/2000/svg">
                        <path fill="currentColor" fill-rule="evenodd" d="M112 248L145 286 171 286 140 248 140 240 172 84 118 49 43 165 43 244 119 324 143 348 212 348 311 245 311 165 236 48 182 83 214 239 214 248 184 286 209 286 244 247 209 177 209 173 220 162 218 151 225 139 242 137 252 149 251 159 245 167 225 167 218 175 252 243 252 249 215 289 208 304 198 314 174 320 155 313 147 305 139 289 102 249 102 243 136 178 129 167 114 169 103 159 105 143 112 137 123 136 134 144 134 162 144 171 145 177 110 245ZM278 357L226 395 175 416 137 400 101 378 77 359 36 314 14 279 0 248 0 162 109 43 56 8 31 19 17 35 9 59 13 88 27 108 51 85 51 69 46 68 38 56 41 43 51 36 63 37 70 43 73 56 70 63 59 70 58 89 26 118 15 107 6 91 1 64 10 32 29 11 44 3 59 0 118 40 236 40 295 0 320 8 339 25 350 47 352 75 345 97 327 118 295 88 295 70 287 67 281 57 282 46 291 37 303 36 312 42 315 58 309 67 302 70 302 84 327 108 343 81 344 55 336 34 325 21 309 11 297 8 244 43 354 163 353 250 338 282 319 312ZM157 401 174 408 188 405 227 386 263 361 289 337 313 308 346 248 346 165 265 78 319 163 319 245 214 355 140 355 35 245 35 164 92 75 7 165 7 246 28 289 54 325 87 358 120 382ZM191 47 130 49 179 79 224 48ZM195 185 176 98 153 219 173 210 187 211 201 218ZM180 243 206 243 201 229 183 218 161 222 152 231 148 241ZM164 309 172 312 189 310 200 302 204 294 150 294 156 304ZM227 153 230 160 239 161 244 151 240 145 233 144 229 146ZM116 160 123 161 127 156 127 149 121 144 111 149 111 157ZM173 250 153 252 178 280 201 250ZM294 61 302 62 307 57 307 50 301 44 294 44 289 49 289 57ZM55 44 48 47 47 58 51 62 60 62 65 56 65 50 61 45Z"/>
                    </svg>
                </span>
                <span class="cybear-response-brand-name">Cybear <span>Care</span></span>
            </a>
        </header>

        <main class="cybear-response-main" id="cybear-response-content">
            <section class="cybear-response-copy" aria-labelledby="cybear-response-title">
                <p class="cybear-response-eyebrow">Application protection</p>
                <h1 class="cybear-response-title" id="cybear-response-title">This request was stopped.</h1>
                <p class="cybear-response-message">
                    Cybear stopped this request before it reached the application. If you believe this was a mistake, return to the application and try again.
                </p>
                <div class="cybear-response-actions">
                    <a class="cybear-response-action" href="/">Return to application</a>
                </div>
            </section>

            <aside class="cybear-response-status" aria-label="Protection status">
                <div class="cybear-response-status-heading">
                    <span class="cybear-response-status-marker" aria-hidden="true"></span>
                    <strong>Request blocked</strong>
                </div>
                <dl>
                    <div>
                        <dt>Protection</dt>
                        <dd>Active</dd>
                    </div>
                    <div>
                        <dt>Security layer</dt>
                        <dd>Laravel application</dd>
                    </div>
                    <div>
                        <dt>Account details</dt>
                        <dd>Not requested</dd>
                    </div>
                    <div>
                        <dt>Incident reference</dt>
                        <dd class="cybear-response-reference">{{ $analysis['incident_id'] ?? Str::uuid() }}</dd>
                    </div>
                    @if(config('app.debug'))
                        <div>
                            <dt>Reason</dt>
                            <dd>{{ $analysis['block_reason'] ?? 'Security rule violation' }}</dd>
                        </div>
                        @if(isset($analysis['rule_id']))
                            <div>
                                <dt>Rule</dt>
                                <dd>{{ $analysis['rule_id'] }}</dd>
                            </div>
                        @endif
                    @endif
                </dl>
            </aside>
        </main>

        <footer class="cybear-response-footer">
            <span>Protected by Cybear Care</span>
            <span class="cybear-response-code">403</span>
        </footer>
    </div>
</body>
</html>
