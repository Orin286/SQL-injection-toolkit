# SQL Injection Toolkit

Advanced SQL injection scanner and exploiter with payload mutation capabilities for penetration testing.

## Features

- **Multi-type SQL Injection Detection**
  - Union-based
  - Boolean-based
  - Error-based
  - Time-based

- **Automatic Vulnerability Scanning**
  - URL parameters
  - POST parameters
  - Form inputs
  - Cookie parameters

- **Database Fingerprinting**
  - MySQL
  - PostgreSQL
  - MSSQL
  - Oracle
  - SQLite

- **Payload Mutation Engine**
  - WAF bypass techniques
  - Case variation
  - Encoding methods
  - Comment injection
  - Whitespace modification

- **Exploitation Capabilities**
  - Database enumeration
  - Table extraction
  - Column discovery
  - Data extraction

## Installation

```bash
git clone <repository-url>
cd sql_injection_toolkit
pip install -r requirements.txt
```

## Usage

### Basic Scanning

```bash
python main.py -u "http://example.com/page.php?id=1"
```

### Advanced Scanning with POST Data

```bash
python main.py -u "http://example.com/login.php" --data "username=admin&password=test"
```

### With Cookies

```bash
python main.py -u "http://example.com/profile.php" --cookie "session=abc123; user=admin"
```

### Enable Payload Mutation

```bash
python main.py -u "http://example.com/page.php?id=1" --mutate
```

### High-Level Scanning

```bash
python main.py -u "http://example.com/page.php?id=1" --level 5 --risk 3
```

## Options

- `-u, --url`: Target URL (required)
- `--data`: POST data (format: "param1=value1&param2=value2")
- `--cookie`: Cookie string
- `--threads`: Number of threads (default: 10)
- `--timeout`: Request timeout in seconds (default: 10)
- `--level`: Scan level 1-5 (default: 1)
- `--risk`: Risk level 1-3 (default: 1)
- `--mutate`: Enable payload mutation
- `--output`: Save results to file
- `--verbose`: Verbose output

## Scan Levels

1. **Level 1**: Basic payloads (quotes, simple injections)
2. **Level 2**: Union-based payloads
3. **Level 3**: Error-based payloads
4. **Level 4**: Boolean-based payloads
5. **Level 5**: Time-based payloads

## Risk Levels

1. **Low Risk**: Non-destructive payloads only
2. **Medium Risk**: Includes some disruptive payloads
3. **High Risk**: All payloads including heavy time-based attacks

## Examples

### Scan with Custom Settings

```bash
python main.py -u "http://test.com/vuln.php" --level 3 --risk 2 --threads 20 --timeout 15
```

### Save Results

```bash
python main.py -u "http://test.com/vuln.php" --output results.txt
```

### Verbose Mode

```bash
python main.py -u "http://test.com/vuln.php" --verbose
```

## Architecture

```
sql_injection_toolkit/
├── main.py                 # Main entry point
├── core/
│   ├── scanner.py          # Vulnerability scanner
│   ├── exploiter.py        # Exploitation engine
│   └── mutator.py          # Payload mutation
├── utils/
│   └── logger.py           # Logging utilities
└── requirements.txt        # Dependencies
```

## Payload Mutation Techniques

- **Case Variation**: Random upper/lower case
- **Encoding**: URL, hex, double URL encoding
- **Comments**: Inline comments to break patterns
- **Whitespace**: Tab, newline, comment whitespace
- **Concatenation**: MySQL CONCAT functions
- **Character Encoding**: CHAR() function encoding

## Database Support

- **MySQL**: Full support with information_schema
- **PostgreSQL**: pg_tables and system catalogs
- **MSSQL**: sysobjects and syscolumns
- **Oracle**: ALL_TABLES and ALL_TAB_COLUMNS
- **SQLite**: sqlite_master table

## Legal Disclaimer

This tool is for educational purposes and authorized penetration testing only. Users are responsible for obtaining proper authorization before testing any systems. The authors are not responsible for any misuse of this software.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Changelog

### v1.0.0
- Initial release
- Multi-database support
- Payload mutation engine
- Web interface
- Export capabilities
