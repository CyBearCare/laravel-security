<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Challenge - Cybear Security</title>
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
        .challenge-icon {
            font-size: 4em;
            color: #f39c12;
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
        .challenge-form {
            margin: 30px 0;
        }
        .math-challenge {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            font-size: 1.5em;
            color: #2c3e50;
        }
        input[type="text"] {
            padding: 15px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 1.2em;
            width: 100px;
            text-align: center;
            margin: 0 10px;
        }
        input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
        }
        .submit-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 30px;
            border: none;
            border-radius: 8px;
            font-size: 1.1em;
            cursor: pointer;
            margin-top: 20px;
            transition: transform 0.2s;
        }
        .submit-btn:hover {
            transform: translateY(-2px);
        }
        .progress-bar {
            width: 100%;
            height: 4px;
            background: #e0e0e0;
            border-radius: 2px;
            margin: 20px 0;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            width: 0%;
            animation: progress 30s linear forwards;
        }
        @keyframes progress {
            to { width: 100%; }
        }
        .info {
            background: #e8f4fd;
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
            color: #2c3e50;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="challenge-icon">🔍</div>
        
        <h1>Security Challenge</h1>
        <p class="subtitle">Please complete this challenge to verify you're human</p>
        
        <form method="POST" class="challenge-form">
            @csrf
            <div class="math-challenge">
                @php
                    $num1 = rand(1, 20);
                    $num2 = rand(1, 20);
                    $answer = $num1 + $num2;
                    session(['cybear_math_answer' => $answer]);
                @endphp
                {{ $num1 }} + {{ $num2 }} = 
                <input type="text" name="math_answer" required autocomplete="off">
            </div>
            
            <input type="hidden" name="cybear_challenge_response" value="{{ $challenge_token }}">
            
            <div class="progress-bar">
                <div class="progress-fill"></div>
            </div>
            
            <button type="submit" class="submit-btn">Verify & Continue</button>
        </form>
        
        <div class="info">
            <p>This security challenge helps protect the website from automated attacks.</p>
            <p><strong>Protected by Cybear Security</strong></p>
        </div>
    </div>

    <script>
        // Auto-submit when math is solved correctly
        document.querySelector('input[name="math_answer"]').addEventListener('input', function(e) {
            const answer = parseInt(e.target.value);
            if (answer === {{ session('cybear_math_answer', 0) }}) {
                setTimeout(() => {
                    document.querySelector('.challenge-form').submit();
                }, 500);
            }
        });

        // Auto-redirect after 30 seconds
        setTimeout(() => {
            window.location.reload();
        }, 30000);
    </script>
</body>
</html>