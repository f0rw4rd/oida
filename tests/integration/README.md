# OIDA Integration Tests

Comprehensive integration tests for OIDA scanners against Docker mock services.

## Overview

This test suite validates that all OIDA protocol scanners work correctly against realistic mock industrial services running in a Docker container.

## Test Structure

```
tests/integration/
├── test_mock_services.py    # Main unittest-based integration tests
├── pytest_tests.py          # Pytest-based tests with fixtures
├── run_tests.py             # Enhanced test runner with CLI options
├── Makefile                 # Convenient test commands
└── README.md               # This file
```

## Quick Start

### 1. Install Dependencies

```bash
# Install package with all protocol extras + dev tools
pip install -e .[dev,all]
```

### 2. Run All Tests

```bash
pytest tests/
```

### 3. Run Specific Suites

```bash
pytest tests/unit                  # Unit tests only
pytest tests/integration           # Integration tests (some need docker mocks)
pytest tests/integration/pcap      # PCAP listener integration tests
```

## Test Categories

### 🔌 Connectivity Tests
- Verify all mock services are responsive
- Test basic TCP/UDP connectivity
- Validate Docker container health

### 🛠️ Protocol Scanner Tests
- **Modbus TCP**: Device info, registers, coils discovery
- **OPC UA**: Server info, namespaces, nodes discovery  
- **IEC 104**: Data points, interrogation, ASDU handling
- **ADS**: Device info, symbols, PLC variables
- **MMS/IEC 61850**: Logical devices, nodes, data objects
- **EtherNet/IP**: Identity, classes, attributes discovery

### ⚡ Concurrency Tests
- Multiple simultaneous connections
- Rapid successive connections
- Service stability under load

### 🚀 Performance Tests
- Response time measurements
- Throughput testing
- Resource usage validation

## Command Line Options

### run_tests.py Options

```bash
# Test specific protocol only
python run_tests.py --protocol modbus

# Quick connectivity tests
python run_tests.py --quick

# Test concurrent connections
python run_tests.py --concurrent

# Custom timeout
python run_tests.py --timeout 300

# Skip container management (assume running)
python run_tests.py --no-container

# Generate reports only
python run_tests.py --report-only
```

### Make Targets

```bash
make help              # Show all available targets
make test              # Run full test suite
make test-quick        # Quick connectivity tests
make test-concurrent   # Concurrent connection tests
make test-single PROTOCOL=modbus  # Test specific protocol
make pytest            # Run pytest-based tests
make build-container   # Build mock services container
make run-container     # Start mock services
make stop-container    # Stop mock services
make logs             # Show container logs
make clean            # Clean up test artifacts
```

### Pytest Options

```bash
# Run all pytest tests
pytest pytest_tests.py -v

# Run specific test class
pytest pytest_tests.py::TestModbus -v

# Run with coverage
pytest pytest_tests.py --cov=../../oida --cov-report=html

# Run performance tests
pytest pytest_tests.py -k "stress" -v

# Run with custom markers
pytest pytest_tests.py -m "slow" -v
```

## Test Configuration

### Environment Variables

```bash
export OIDA_TEST_HOST=127.0.0.1     # Mock services host
export OIDA_TEST_TIMEOUT=30         # Default timeout
export OIDA_TEST_VERBOSE=1          # Verbose output
```

### Protocol Ports

| Protocol | Port | Service |
|----------|------|---------|
| Modbus TCP | 502 | Mock PLC |
| OPC UA | 4840 | Mock OPC Server |
| IEC 104 | 2404 | Mock RTU |
| ADS | 48898 | Mock TwinCAT |
| MMS | 102 | Mock IED |
| EtherNet/IP | 44818 | Mock Device |

## Test Results

### Reports Generated

- **JSON Report**: `test_results.json` - Machine-readable results
- **HTML Report**: `test_report.html` - Visual test report
- **Markdown Report**: `test_report.md` - Documentation-friendly format

### Example Test Output

```
==========================================
OIDA Mock Services Integration Tests
==========================================

Testing MODBUS scanner...
  ✅ MODBUS test passed

Testing OPC UA scanner...
  ✅ OPC UA test passed

Testing IEC 104 scanner...
  ✅ IEC 104 test passed

...

==========================================
TEST SUMMARY REPORT
==========================================
Total Tests:    12
Passed:         10
Failed:         1
Errors:         1
Success Rate:   83.3%
```

## Troubleshooting

### Common Issues

#### Container Fails to Start
```bash
# Check Docker status
docker info

# Check port conflicts
netstat -tlnp | grep -E ':(502|4840|2404|48898|102|44818)\s'

# View container logs
make logs
```

#### Service Connection Timeouts
```bash
# Check service responsiveness
make check-services

# Increase timeout
python run_tests.py --timeout 60

# Test individual services
make test-modbus
make test-opcua
```

#### Missing Dependencies
```bash
# Install missing protocol libraries
pip install pymodbus asyncua c104 pyads cpppo

# Check dependencies
python -c "import oida; print('OIDA imported successfully')"
```

#### Permission Issues
```bash
# Docker permission issues
sudo usermod -aG docker $USER
newgrp docker

# Port binding issues (< 1024)
sudo python run_tests.py
```

### Debug Mode

```bash
# Run with maximum verbosity
python run_tests.py --verbose --verbose

# Debug individual scanner
python -c "
from oida.protocols.modbus import ModbusScanner
scanner = ModbusScanner({'rhost': '127.0.0.1', 'rport': 502, 'debug': True})
result = scanner.run_scan()
print(result)
"

# Check container internals
docker exec -it oida-mock-test bash
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: OIDA Integration Tests

on: [push, pull_request]

jobs:
  integration-tests:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        cd tests/integration
        make install
    
    - name: Run integration tests
      run: |
        cd tests/integration
        make ci-test
    
    - name: Upload test results
      uses: actions/upload-artifact@v3
      with:
        name: test-results
        path: tests/integration/results/
```

### Jenkins Pipeline Example

```groovy
pipeline {
    agent any
    
    stages {
        stage('Setup') {
            steps {
                sh 'cd tests/integration && make install'
            }
        }
        
        stage('Build Services') {
            steps {
                sh 'cd tests/integration && make build-container'
            }
        }
        
        stage('Integration Tests') {
            steps {
                sh 'cd tests/integration && make test'
            }
        }
        
        stage('Performance Tests') {
            steps {
                sh 'cd tests/integration && make perf-test'
            }
        }
    }
    
    post {
        always {
            sh 'cd tests/integration && make stop-container'
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'tests/integration/results',
                reportFiles: 'test_report.html',
                reportName: 'Integration Test Report'
            ])
        }
    }
}
```

## Development

### Adding New Tests

1. **Add to unittest suite** (`test_mock_services.py`):
```python
def test_new_protocol_scanner(self):
    """Test new protocol scanner"""
    expected = {'key': 'value'}
    result = self._run_scanner_test('new_protocol', expected)
    # Add specific validations
```

2. **Add pytest test** (`pytest_tests.py`):
```python
class TestNewProtocol:
    def test_connectivity(self, mock_service, mock_host):
        assert _check_port_open(mock_host, 9999)
    
    def test_scanner_basic(self, mock_service, mock_host):
        # Test implementation
```

3. **Add to Makefile**:
```makefile
test-newprotocol:
    $(PYTHON) -c "from oida.protocols.newprotocol import NewProtocolScanner; ..."
```

### Extending Mock Services

1. Create new mock service in `docker/mock_services/`
2. Add to `docker/start_services.sh`
3. Update `docker/docker-compose.yml` ports
4. Add tests for new service

## Security Considerations

⚠️ **Test Environment Only**: These tests use mock services without authentication or encryption. Never run against production systems.

- All mock services accept anonymous connections
- No data validation or sanitization
- Designed for controlled testing environments only
- Services may accept dangerous commands for testing purposes

## Performance Benchmarks

Expected performance baselines:

| Test Type | Target Time | Tolerance |
|-----------|-------------|-----------|
| Quick Tests | < 30s | ±10s |
| Full Suite | < 5min | ±2min |
| Single Protocol | < 30s | ±15s |
| Concurrent (3x) | < 60s | ±30s |

## License

This test suite is part of the OIDA project and follows the same license terms.