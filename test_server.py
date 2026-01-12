#!/usr/bin/env python3
"""
Simple test server for SQL injection testing
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import json

class TestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            html = """
            <html>
            <head><title>SQL Injection Test Page</title></head>
            <body>
                <h1>SQL Injection Test Page</h1>
                
                <h2>Test 1: GET Parameter</h2>
                <a href="/test?id=1">Test with id=1</a><br>
                <a href="/test?id=1' OR '1'='1">Test with SQL injection</a>
                
                <h2>Test 2: Search</h2>
                <form method="GET" action="/search">
                    <input type="text" name="q" placeholder="Search...">
                    <input type="submit" value="Search">
                </form>
                
                <h2>Test 3: Login Form</h2>
                <form method="POST" action="/login">
                    <input type="text" name="username" placeholder="Username"><br>
                    <input type="password" name="password" placeholder="Password"><br>
                    <input type="submit" value="Login">
                </form>
            </body>
            </html>
            """
            self.wfile.write(html.encode())
            
        elif self.path.startswith('/test'):
            # Parse query parameters
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            # Simulate SQL injection vulnerability
            if 'id' in params:
                user_id = params['id'][0]
                
                # Check for SQL injection patterns
                if "'" in user_id or '"' in user_id:
                    # Simulate SQL error
                    response = f"SQL Error: You have an error in your SQL syntax near '{user_id}'"
                elif 'OR' in user_id.upper() and '1=1' in user_id:
                    # Simulate successful injection
                    response = "Welcome admin! Your ID: 1<br>Username: admin<br>Email: admin@test.com"
                else:
                    # Normal response
                    response = f"User ID: {user_id}<br>Username: user{user_id}<br>Email: user{user_id}@test.com"
                
                html = f"""
                <html>
                <head><title>Test Results</title></head>
                <body>
                    <h2>Test Results</h2>
                    <p>Query: SELECT * FROM users WHERE id = {user_id}</p>
                    <p>Results:</p>
                    <p>{response}</p>
                    <a href="/">Back</a>
                </body>
                </html>
                """
                self.wfile.write(html.encode())
            else:
                self.send_error(400)
                
        elif self.path.startswith('/search'):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            if 'q' in params:
                query = params['q'][0]
                
                # Simulate search with SQL injection
                if "'" in query or '"' in query:
                    results = f"SQL Error: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /search.php on line 15"
                else:
                    results = f"Search results for '{query}':<br>Found 3 items matching your query."
                
                html = f"""
                <html>
                <head><title>Search Results</title></head>
                <body>
                    <h2>Search Results</h2>
                    <p>Query: SELECT * FROM products WHERE name LIKE '%{query}%'</p>
                    <p>{results}</p>
                    <a href="/">Back</a>
                </body>
                </html>
                """
                self.wfile.write(html.encode())
            else:
                self.send_error(400)
        else:
            self.send_error(404)
    
    def do_POST(self):
        if self.path == '/login':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            if 'username' in params and 'password' in params:
                username = params['username'][0]
                password = params['password'][0]
                
                # Simulate SQL injection in login
                if "'" in username or "'" in password:
                    if "OR" in username.upper() and "1=1" in username:
                        response = "Login successful! Welcome admin!"
                    else:
                        response = f"SQL Error: You have an error in your SQL syntax near '{username}'"
                else:
                    response = f"Login failed for user: {username}"
                
                html = f"""
                <html>
                <head><title>Login Results</title></head>
                <body>
                    <h2>Login Results</h2>
                    <p>Query: SELECT * FROM users WHERE username='{username}' AND password='{password}'</p>
                    <p>{response}</p>
                    <a href="/">Back</a>
                </body>
                </html>
                """
                self.wfile.write(html.encode())
            else:
                self.send_error(400)
        else:
            self.send_error(404)

def run_server():
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, TestHandler)
    print("Test server running on http://localhost:8080")
    print("Press Ctrl+C to stop")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()
