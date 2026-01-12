#!/usr/bin/env python3
"""
Web Interface for SQL Injection Toolkit
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, jsonify, session
import threading
import time
import uuid
from core.scanner import SQLScanner
from core.exploiter import SQLExploiter
from core.mutator import PayloadMutator
from utils.logger import setup_logger

app = Flask(__name__)
app.secret_key = 'sql_injection_toolkit_secret_key'

# Global dictionary to store scan results
scan_results = {}
scan_status = {}

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    """Start SQL injection scan"""
    try:
        data = request.get_json()
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Initialize scan status
        scan_status[scan_id] = {
            'status': 'running',
            'progress': 0,
            'vulnerabilities': [],
            'current_target': data.get('url', ''),
            'start_time': time.time()
        }
        
        # Start scan in background thread
        thread = threading.Thread(target=run_scan, args=(scan_id, data))
        thread.daemon = True
        thread.start()
        
        return jsonify({'scan_id': scan_id, 'status': 'started'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def run_scan(scan_id, data):
    """Run scan in background"""
    try:
        # Extract parameters
        url = data.get('url')
        post_data = data.get('data', '')
        cookies = data.get('cookies', '')
        level = int(data.get('level', 1))
        risk = int(data.get('risk', 1))
        threads = int(data.get('threads', 10))
        timeout = int(data.get('timeout', 10))
        mutate = data.get('mutate', False)
        
        # Update status
        scan_status[scan_id]['progress'] = 10
        scan_status[scan_id]['current_target'] = url
        
        # Initialize scanner
        scanner = SQLScanner(
            threads=threads,
            timeout=timeout,
            level=level,
            risk=risk
        )
        
        # Update progress
        scan_status[scan_id]['progress'] = 20
        
        # Scan target
        vulnerabilities = scanner.scan_target(
            url=url,
            data=post_data if post_data else None,
            cookies=cookies if cookies else None
        )
        
        # Update progress
        scan_status[scan_id]['progress'] = 60
        scan_status[scan_id]['vulnerabilities'] = vulnerabilities
        
        if vulnerabilities:
            # Initialize exploiter
            exploiter = SQLExploiter()
            mutator = PayloadMutator() if mutate else None
            
            exploitation_results = []
            
            for i, vuln in enumerate(vulnerabilities):
                # Update progress
                progress = 60 + (30 * (i + 1) / len(vulnerabilities))
                scan_status[scan_id]['progress'] = progress
                scan_status[scan_id]['current_target'] = f"Exploiting: {vuln['parameter']}"
                
                # Exploit vulnerability
                result = exploiter.exploit(vuln, mutate=mutate, mutator=mutator)
                if result:
                    vuln['exploitation'] = result
                    exploitation_results.append(result)
            
            scan_status[scan_id]['exploitation_results'] = exploitation_results
        
        # Complete scan
        scan_status[scan_id]['status'] = 'completed'
        scan_status[scan_id]['progress'] = 100
        scan_status[scan_id]['end_time'] = time.time()
        
        # Store results
        scan_results[scan_id] = {
            'scan_id': scan_id,
            'target': url,
            'parameters': data,
            'vulnerabilities': vulnerabilities,
            'timestamp': time.time(),
            'duration': scan_status[scan_id]['end_time'] - scan_status[scan_id]['start_time']
        }
        
    except Exception as e:
        scan_status[scan_id]['status'] = 'error'
        scan_status[scan_id]['error'] = str(e)

@app.route('/status/<scan_id>')
def get_scan_status(scan_id):
    """Get scan status"""
    if scan_id in scan_status:
        return jsonify(scan_status[scan_id])
    else:
        return jsonify({'error': 'Scan not found'}), 404

@app.route('/results/<scan_id>')
def get_scan_results(scan_id):
    """Get scan results"""
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    else:
        return jsonify({'error': 'Results not found'}), 404

@app.route('/history')
def scan_history():
    """Scan history page"""
    return render_template('history.html', scans=scan_results)

@app.route('/api/scans')
def api_scans():
    """API endpoint for all scans"""
    return jsonify(list(scan_results.values()))

@app.route('/mutator', methods=['POST'])
def test_mutator():
    """Test payload mutator"""
    try:
        data = request.get_json()
        payload = data.get('payload', '')
        count = int(data.get('count', 10))
        
        mutator = PayloadMutator()
        mutated = mutator.generate_advanced_payloads(payload, count)
        
        return jsonify({
            'original': payload,
            'mutated': mutated,
            'count': len(mutated)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/help')
def help_page():
    """Help/documentation page"""
    return render_template('help.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
