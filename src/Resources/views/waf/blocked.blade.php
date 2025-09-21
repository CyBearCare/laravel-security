<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Blocked - Cybear Care</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            color: #333;
        }
        .container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 40px;
            max-width: 500px;
            text-align: center;
        }
        .shield-icon {
            font-size: 4em;
            color: #e74c3c;
            margin-bottom: 20px;
        }
        h1 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 2em;
        }
        .subtitle {
            color: #7f8c8d;
            margin-bottom: 30px;
            font-size: 1.1em;
        }
        .details {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            text-align: left;
        }
        .detail-item {
            margin: 10px 0;
            font-size: 0.9em;
        }
        .detail-label {
            font-weight: bold;
            color: #2c3e50;
        }
        .support-info {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
            color: #7f8c8d;
            font-size: 0.9em;
        }
        .incident-id {
            font-family: 'Courier New', monospace;
            background: #e8f4fd;
            padding: 5px 10px;
            border-radius: 4px;
            display: inline-block;
            margin: 0 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="shield-icon">🛡️</div>
        
        <h1>Access Blocked</h1>
        <p class="subtitle">Your request has been blocked by our security system</p>
        
        <div class="details">
            <div class="detail-item">
                <span class="detail-label">Reason:</span> 
                @if(config('app.debug'))
                    {{ $analysis['block_reason'] ?? 'Security rule violation' }}
                @else
                    Security rule violation
                @endif
            </div>
            @if(isset($analysis['rule_id']) && config('app.debug'))
            <div class="detail-item">
                <span class="detail-label">Rule ID:</span> 
                <span class="incident-id">{{ $analysis['rule_id'] }}</span>
            </div>
            @endif
            <div class="detail-item">
                <span class="detail-label">Time:</span> 
                {{ now()->format('Y-m-d H:i:s T') }}
            </div>
            <div class="detail-item">
                <span class="detail-label">Incident ID:</span> 
                <span class="incident-id">{{ $analysis['incident_id'] ?? Str::uuid() }}</span>
            </div>
        </div>
        
        <div class="support-info">
            <p>If you believe this is an error, please contact the site administrator with the incident ID above.</p>
            <p><strong>Protected by Cybear Care</strong></p>
        </div>
    </div>
</body>
</html>