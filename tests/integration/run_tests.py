#!/usr/bin/env python3
"""
Enhanced test runner for OIDA integration tests
"""

import argparse
import sys
import json
import os
from pathlib import Path

# Add OIDA to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from test_mock_services import TestRunner, MockServicesIntegrationTest


def main():
    """Main test runner with command line options"""
    parser = argparse.ArgumentParser(
        description="Run OIDA integration tests against mock services",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_tests.py                     # Run all tests
  python run_tests.py --protocol modbus   # Test only Modbus
  python run_tests.py --quick             # Quick test (basic connectivity)
  python run_tests.py --concurrent        # Test concurrent connections
  python run_tests.py --report-only       # Generate reports only
        """,
    )

    parser.add_argument(
        "--protocol",
        choices=["modbus", "opcua", "iec104", "ads", "mms", "ethernetip"],
        help="Test specific protocol only",
    )

    parser.add_argument("--quick", action="store_true", help="Run quick connectivity tests only")

    parser.add_argument("--concurrent", action="store_true", help="Test concurrent connections")

    parser.add_argument(
        "--timeout", type=int, default=300, help="Test timeout in seconds (default: 300)"
    )

    parser.add_argument("--verbose", "-v", action="count", default=1, help="Increase verbosity")

    parser.add_argument(
        "--no-container",
        action="store_true",
        help="Skip container management (assume services running)",
    )

    parser.add_argument(
        "--report-only", action="store_true", help="Generate reports from existing test results"
    )

    parser.add_argument(
        "--output-dir",
        default=str(Path(__file__).parent / "results"),
        help="Output directory for test results",
    )

    args = parser.parse_args()

    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)

    if args.report_only:
        generate_reports_only(args.output_dir)
        return 0

    # Run tests
    success = run_integration_tests(args)

    return 0 if success else 1


def run_integration_tests(args):
    """Run integration tests with specified options"""
    print("=" * 80)
    print("OIDA Mock Services Integration Test Suite")
    print("=" * 80)
    print(f"Protocol filter: {args.protocol or 'All'}")
    print(f"Test mode: {'Quick' if args.quick else 'Concurrent' if args.concurrent else 'Full'}")
    print(f"Timeout: {args.timeout}s")
    print(f"Container management: {'Disabled' if args.no_container else 'Enabled'}")
    print("=" * 80)

    # Set up test environment
    if not args.no_container:
        print("Setting up test environment...")
        if not setup_test_environment():
            print("[FAIL] Failed to set up test environment")
            return False

    try:
        if args.quick:
            return run_quick_tests(args)
        elif args.concurrent:
            return run_concurrent_tests(args)
        elif args.protocol:
            return run_single_protocol_test(args)
        else:
            return run_full_test_suite(args)

    except KeyboardInterrupt:
        print("\nWARNING: Tests interrupted by user")
        return False
    except Exception as e:
        print(f"[FAIL] Test execution failed: {e}")
        return False


def setup_test_environment():
    """Set up the test environment"""
    try:
        import docker

        client = docker.from_env()

        # Check if Docker is available
        client.ping()
        print("[OK] Docker is available")

        # Check if mock services container exists
        try:
            container = client.containers.get("oida-mock-test")
            if container.status != "running":
                print("Starting existing container...")
                container.start()
            else:
                print("[OK] Mock services container already running")
        except docker.errors.NotFound:
            print("[OK] Will create new container during tests")

        return True

    except Exception as e:
        print(f"[FAIL] Docker setup failed: {e}")
        return False


def run_quick_tests(args):
    """Run quick connectivity tests"""
    print("\nRunning quick connectivity tests...")

    import unittest

    # Create custom test suite with only connectivity tests
    suite = unittest.TestSuite()
    suite.addTest(MockServicesIntegrationTest("test_all_services_responsive"))
    suite.addTest(MockServicesIntegrationTest("test_container_health"))

    runner = unittest.TextTestRunner(verbosity=args.verbose)
    result = runner.run(suite)

    success = result.wasSuccessful()
    print(f"\n[OK] Quick tests {'PASSED' if success else 'FAILED'}")

    return success


def run_concurrent_tests(args):
    """Run concurrent connection tests"""
    print("\nRunning concurrent connection tests...")

    import unittest

    suite = unittest.TestSuite()
    suite.addTest(MockServicesIntegrationTest("test_concurrent_connections"))
    suite.addTest(MockServicesIntegrationTest("test_all_services_responsive"))

    runner = unittest.TextTestRunner(verbosity=args.verbose)
    result = runner.run(suite)

    success = result.wasSuccessful()
    print(f"\n[OK] Concurrent tests {'PASSED' if success else 'FAILED'}")

    return success


def run_single_protocol_test(args):
    """Run tests for a single protocol"""
    protocol = args.protocol
    print(f"\nRunning {protocol.upper()} protocol tests...")

    import unittest

    # Map protocol to test method
    test_methods = {
        "modbus": "test_modbus_scanner",
        "opcua": "test_opcua_scanner",
        "iec104": "test_iec104_scanner",
        "ads": "test_ads_scanner",
        "mms": "test_mms_scanner",
        "ethernetip": "test_ethernetip_scanner",
    }

    if protocol not in test_methods:
        print(f"[FAIL] Unknown protocol: {protocol}")
        return False

    suite = unittest.TestSuite()
    suite.addTest(MockServicesIntegrationTest("test_all_services_responsive"))
    suite.addTest(MockServicesIntegrationTest(test_methods[protocol]))

    runner = unittest.TextTestRunner(verbosity=args.verbose)
    result = runner.run(suite)

    success = result.wasSuccessful()
    print(f"\n[OK] {protocol.upper()} tests {'PASSED' if success else 'FAILED'}")

    return success


def run_full_test_suite(args):
    """Run the complete test suite"""
    print("\nRunning full integration test suite...")

    runner = TestRunner()
    success = runner.run_tests(verbosity=args.verbose)

    print(f"\n[OK] Full test suite {'PASSED' if success else 'FAILED'}")

    return success


def generate_reports_only(output_dir):
    """Generate reports from existing test results"""
    print("Generating test reports...")

    results_file = os.path.join(output_dir, "test_results.json")

    if not os.path.exists(results_file):
        print("[FAIL] No test results found. Run tests first.")
        return

    try:
        with open(results_file, "r") as f:
            results = json.load(f)

        # Generate HTML report
        generate_html_report(results, output_dir)

        # Generate markdown report
        generate_markdown_report(results, output_dir)

        print("[OK] Reports generated successfully")

    except Exception as e:
        print(f"[FAIL] Failed to generate reports: {e}")


def generate_html_report(results, output_dir):
    """Generate HTML test report"""
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>OIDA Integration Test Results</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .metric {{ background: #e9f7ef; padding: 15px; border-radius: 5px; text-align: center; }}
        .metric.failed {{ background: #fadbd8; }}
        .metric.error {{ background: #fdf2e9; }}
        .test-results {{ margin-top: 30px; }}
        .test {{ margin: 10px 0; padding: 15px; border-left: 4px solid #ccc; }}
        .test.passed {{ border-left-color: #28a745; background: #f8fff9; }}
        .test.failed {{ border-left-color: #dc3545; background: #fff8f8; }}
        .test.error {{ border-left-color: #ffc107; background: #fffef7; }}
        pre {{ background: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>OIDA Integration Test Results</h1>
        <p>Generated: {results["timestamp"]}</p>
    </div>
    
    <div class="summary">
        <div class="metric">
            <h3>{results["total_tests"]}</h3>
            <p>Total Tests</p>
        </div>
        <div class="metric">
            <h3>{results["passed"]}</h3>
            <p>Passed</p>
        </div>
        <div class="metric failed">
            <h3>{results["failed"]}</h3>
            <p>Failed</p>
        </div>
        <div class="metric error">
            <h3>{results["errors"]}</h3>
            <p>Errors</p>
        </div>
        <div class="metric">
            <h3>{results["success_rate"]:.1f}%</h3>
            <p>Success Rate</p>
        </div>
    </div>
    
    <div class="test-results">
        <h2>Test Results</h2>
"""

    # Add failures
    if results["failures"]:
        html_content += "<h3>Failures</h3>"
        for failure in results["failures"]:
            html_content += f"""
        <div class="test failed">
            <h4>{failure["test"]}</h4>
            <pre>{failure["message"]}</pre>
        </div>
"""

    # Add errors
    if results["errors"]:
        html_content += "<h3>Errors</h3>"
        for error in results["errors"]:
            html_content += f"""
        <div class="test error">
            <h4>{error["test"]}</h4>
            <pre>{error["message"]}</pre>
        </div>
"""

    html_content += """
    </div>
</body>
</html>
"""

    html_file = os.path.join(output_dir, "test_report.html")
    with open(html_file, "w") as f:
        f.write(html_content)

    print(f"HTML report: {html_file}")


def generate_markdown_report(results, output_dir):
    """Generate Markdown test report"""
    md_content = f"""# OIDA Integration Test Results

**Generated:** {results["timestamp"]}

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | {results["total_tests"]} |
| Passed | {results["passed"]} |
| Failed | {results["failed"]} |
| Errors | {results["errors"]} |
| Success Rate | {results["success_rate"]:.1f}% |

## Test Results

"""

    if results["failures"]:
        md_content += "### Failures\n\n"
        for failure in results["failures"]:
            md_content += f"#### {failure['test']}\n\n"
            md_content += f"```\n{failure['message']}\n```\n\n"

    if results["errors"]:
        md_content += "### Errors\n\n"
        for error in results["errors"]:
            md_content += f"#### {error['test']}\n\n"
            md_content += f"```\n{error['message']}\n```\n\n"

    md_file = os.path.join(output_dir, "test_report.md")
    with open(md_file, "w") as f:
        f.write(md_content)

    print(f"Markdown report: {md_file}")


if __name__ == "__main__":
    sys.exit(main())
