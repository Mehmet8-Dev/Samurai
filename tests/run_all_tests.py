#!/usr/bin/env python3
"""
MASTER TEST RUNNER - Samurai Full Stack Verification
Tüm testleri çalıştırır ve detaylı rapor üretir
"""

import sys
import os
import time
import subprocess
from datetime import datetime
from pathlib import Path

# Colors for output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.OKCYAN}{'='*80}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.OKCYAN}{text.center(80)}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.OKCYAN}{'='*80}{Colors.ENDC}\n")

def print_section(text):
    print(f"\n{Colors.BOLD}{Colors.OKBLUE}▶ {text}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}{'-'*80}{Colors.ENDC}\n")

def run_test_file(test_file):
    """Single test file'ı çalıştır"""
    print(f"{Colors.WARNING}Running: {test_file}{Colors.ENDC}")
    
    start_time = time.time()
    
    try:
        result = subprocess.run(
            [sys.executable, str(test_file)],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        elapsed = time.time() - start_time
        
        # Output göster
        print(result.stdout)
        if result.stderr:
            print(f"{Colors.WARNING}STDERR:{Colors.ENDC}")
            print(result.stderr)
        
        success = result.returncode == 0
        
        return {
            'file': test_file.name,
            'success': success,
            'elapsed': elapsed,
            'returncode': result.returncode
        }
    
    except subprocess.TimeoutExpired:
        print(f"{Colors.FAIL}✗ Test timeout (5 minutes){Colors.ENDC}")
        return {
            'file': test_file.name,
            'success': False,
            'elapsed': 300,
            'returncode': -1
        }
    except Exception as e:
        print(f"{Colors.FAIL}✗ Error running test: {e}{Colors.ENDC}")
        return {
            'file': test_file.name,
            'success': False,
            'elapsed': 0,
            'returncode': -1
        }

def main():
    """Master test runner"""
    
    print_header("🔍 DDOSAMURAI COMPREHENSIVE TEST SUITE 🔍")
    
    print(f"{Colors.BOLD}Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
    print(f"{Colors.BOLD}Python version: {sys.version.split()[0]}{Colors.ENDC}")
    print(f"{Colors.BOLD}Working directory: {os.getcwd()}{Colors.ENDC}\n")
    
    # Test dizinini bul
    test_dir = Path(__file__).parent
    if not test_dir.exists():
        print(f"{Colors.FAIL}✗ Test directory not found: {test_dir}{Colors.ENDC}")
        sys.exit(1)
    
    # Test file'larını bul
    test_files = [
        test_dir / "test_comprehensive_full.py",
        test_dir / "test_zmq_wire_contract.py",
        test_dir / "test_zmq_m2_cpu_proto.py",
        test_dir / "test_zmq_m3_workers.py",
        test_dir / "test_zmq_m4_orchestrator.py",
        test_dir / "test_zmq_m6_cleanup.py",
        test_dir / "test_zmq_m7_perf.py",
    ]
    
    print_section("TEST FILES DETECTED")
    for test_file in test_files:
        if test_file.exists():
            print(f"{Colors.OKGREEN}✓ {test_file.name}{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}✗ {test_file.name} NOT FOUND{Colors.ENDC}")
    
    # Testleri çalıştır
    print_section("RUNNING TESTS")
    
    results = []
    total_start = time.time()
    
    for test_file in test_files:
        if test_file.exists():
            print_section(f"TEST SUITE: {test_file.name}")
            result = run_test_file(test_file)
            results.append(result)
        else:
            print(f"{Colors.WARNING}⚠ Skipping {test_file.name} (not found){Colors.ENDC}")
    
    total_time = time.time() - total_start
    
    # Özet raporu
    print_header("📊 TEST RESULTS SUMMARY")
    
    print(f"{Colors.BOLD}Total execution time: {total_time:.2f} seconds{Colors.ENDC}\n")
    
    print(f"{Colors.BOLD}Individual results:{Colors.ENDC}")
    print(f"{Colors.BOLD}{'-'*80}{Colors.ENDC}")
    
    passed = 0
    failed = 0
    
    for result in results:
        status = f"{Colors.OKGREEN}✓ PASSED{Colors.ENDC}" if result['success'] else f"{Colors.FAIL}✗ FAILED{Colors.ENDC}"
        print(f"{Colors.BOLD}{result['file']:<40}{Colors.ENDC} {status:<30} {result['elapsed']:>6.2f}s")
        
        if result['success']:
            passed += 1
        else:
            failed += 1
    
    print(f"{Colors.BOLD}{'-'*80}{Colors.ENDC}\n")
    
    # Final summary
    print_section("FINAL SUMMARY")
    
    print(f"{Colors.BOLD}Test suites run: {len(results)}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}Passed: {passed}{Colors.ENDC}")
    print(f"{Colors.FAIL}Failed: {failed}{Colors.ENDC}")
    print(f"{Colors.BOLD}Total time: {total_time:.2f}s{Colors.ENDC}")
    print(f"{Colors.BOLD}End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}\n")
    
    # Recommendations
    print_section("RECOMMENDATIONS")
    
    if failed == 0:
        print(f"{Colors.OKGREEN}{Colors.BOLD}✓ ALL TESTS PASSED!{Colors.ENDC}")
        print(f"\n{Colors.OKGREEN}Your Samurai implementation is correct and ready for deployment.{Colors.ENDC}\n")
        return 0
    else:
        print(f"{Colors.FAIL}{Colors.BOLD}✗ SOME TESTS FAILED{Colors.ENDC}")
        print(f"\n{Colors.FAIL}Please review the failed tests above and fix the issues.{Colors.ENDC}\n")
        return 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}⚠ Test suite interrupted by user{Colors.ENDC}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.FAIL}✗ Unexpected error: {e}{Colors.ENDC}\n")
        sys.exit(1)
