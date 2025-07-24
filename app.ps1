# Import Pode
Import-Module Pode

# Start the Pode web server
Start-PodeServer {
    Add-PodeEndpoint -Address * -Port 8080 -Protocol Http

    # Main page with form and button
    Add-PodeRoute -Method Get -Path "/" -ScriptBlock {
        $html = @"
<html>
    <head>
        <title>Modern PowerShell Web App</title>
        <style>
            body { font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6fa; color: #222; }
            .container { max-width: 600px; margin: 100px auto; background: #fff; border-radius: 8px; box-shadow: 0 2px 8px #0001; padding: 2em; }
            h1 { color: #0078d7; }
            input, button { font-size: 1em; padding: 0.5em; margin: 0.5em 0; }
            .result { margin-top: 1em; color: #0078d7; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Modern PowerShell Web App</h1>
            <form method="post" action="/submit">
                <label for="name">Enter your name:</label><br>
                <input type="text" id="name" name="name" required /><br>
                <button type="submit">Say Hello</button>
            </form>
            <form method="post" action="/button">
                <button type="submit" style="background:#0078d7;color:#fff;">Click Me!</button>
            </form>
        </div>
    </body>
</html>
"@
        Write-PodeHtmlResponse -Value $html
    }

    # Handle form submission
    Add-PodeRoute -Method Post -Path "/submit" -ScriptBlock {
        $name = $WebEvent.Data.name
        $html = @"
<html>
    <head>
        <title>Modern PowerShell Web App</title>
        <style>
            body { font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6fa; color: #222; }
            .container { max-width: 600px; margin: 100px auto; background: #fff; border-radius: 8px; box-shadow: 0 2px 8px #0001; padding: 2em; }
            h1 { color: #0078d7; }
            input, button { font-size: 1em; padding: 0.5em; margin: 0.5em 0; }
            .result { margin-top: 1em; color: #0078d7; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Modern PowerShell Web App</h1>
            <form method="post" action="/submit">
                <label for="name">Enter your name:</label><br>
                <input type="text" id="name" name="name" required /><br>
                <button type="submit">Say Hello</button>
            </form>
            <form method="post" action="/button">
                <button type="submit" style="background:#0078d7;color:#fff;">Click Me!</button>
            </form>
            <div class='result'>Hello, <b>$name</b>! 👋</div>
        </div>
    </body>
</html>
"@
        Write-PodeHtmlResponse -Value $html
    }

    # Handle button click
    Add-PodeRoute -Method Post -Path "/button" -ScriptBlock {
        $html = @"
<html>
    <head>
        <title>Modern PowerShell Web App</title>
        <style>
            body { font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6fa; color: #222; }
            .container { max-width: 600px; margin: 100px auto; background: #fff; border-radius: 8px; box-shadow: 0 2px 8px #0001; padding: 2em; }
            h1 { color: #0078d7; }
            input, button { font-size: 1em; padding: 0.5em; margin: 0.5em 0; }
            .result { margin-top: 1em; color: #0078d7; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Modern PowerShell Web App</h1>
            <form method="post" action="/submit">
                <label for="name">Enter your name:</label><br>
                <input type="text" id="name" name="name" required /><br>
                <button type="submit">Say Hello</button>
            </form>
            <form method="post" action="/button">
                <button type="submit" style="background:#0078d7;color:#fff;">Click Me!</button>
            </form>
            <div class='result'>You clicked the button! 🎉</div>
        </div>
    </body>
</html>
"@
        Write-PodeHtmlResponse -Value $html
    }
}