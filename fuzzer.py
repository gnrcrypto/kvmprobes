#!/usr/bin/env python3
"""
kvmctf_host_fuzzer.py - Host-based KVM 0-day fuzzer for Google kvmCTF
Enhanced with crash detection and analysis
"""

import os
import sys
import subprocess
import time
import json
import signal
import shutil
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict
from datetime import datetime
import socket
import re

# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class FuzzerConfig:
    # VM Configuration
    VM_IMAGE: str = "/root/kvmctf-host/guest/fuzzer/fuzzer.img"
    VM_KERNEL: str = "/root/kvmctf-host/guest/fuzzer/vmlinuz-6.1.0-21-amd64"
    VM_INITRD: str = "/root/kvmctf-host/guest/fuzzer/initrd.img-6.1.0-21-amd64"
    VM_KERNEL_ARGS: str = "root=/dev/sda1 rw console=ttyS0 rootwait nokaslr"
    
    VM_MEMORY: str = "2G"
    VM_CPUS: int = 12
    VM_TIMEOUT: int = 60
    VM_BOOT_TIMEOUT: int = 30
    
    # Fuzzer Configuration
    MAX_CONCURRENT_VMS: int = 1
    TEST_TIMEOUT: int = 30
    COOLDOWN_MS: int = 100
    
    # Paths
    QEMU_BIN: str = "/usr/bin/qemu-system-x86_64"
    RESULTS_DIR: str = "./fuzzer_results"
    
    # Serial communication
    SERIAL_PORT_BASE: int = 4555
    MONITOR_PORT_BASE: int = 4556
    SSH_PORT_BASE: int = 2222
    
    # Host kernel addresses
    HOST_WRITE_FLAG: int = 0xffffffff826279a8
    HOST_READ_FLAG: int = 0xffffffff82b5ee10

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class TestCase:
    id: int
    name: str
    description: str
    category: str
    dangerous: bool = False
    
@dataclass
class CrashInfo:
    type: str  # "panic", "oops", "softlockup", "hardlockup", "bug"
    location: str
    stack_trace: List[str]
    registers: Dict[str, str]
    timestamp: float
    
@dataclass
class TestResult:
    test_id: int
    test_name: str
    status: str
    runtime_ms: int
    crash_info: Optional[CrashInfo] = None
    escape_details: Optional[Dict] = None
    guest_log: str = ""
    test_output: str = ""
    
@dataclass
class EscapeEvent:
    timestamp: str
    test_id: int
    test_name: str
    method: str
    details: Dict
    guest_state: str
    crash_info: Optional[CrashInfo] = None

# ============================================================================
# CRASH ANALYZER
# ============================================================================

class CrashAnalyzer:
    """Analyze kernel crash dumps from guest output"""
    
    CRASH_PATTERNS = {
        "panic": re.compile(r'Kernel panic - not syncing: (.*?)(?:\n|$)'),
        "oops": re.compile(r'------------\[ cut here \]------------(.*?)(?:\n---|$)', re.DOTALL),
        "softlockup": re.compile(r'Watchdog detected soft lockup on CPU \d+(.*?)(?:\n---|$)', re.DOTALL),
        "hardlockup": re.compile(r'Watchdog detected hard LOCKUP on CPU \d+(.*?)(?:\n---|$)', re.DOTALL),
        "bug": re.compile(r'kernel BUG at (.*?):(.*?)(?:\n|$)'),
        "warning": re.compile(r'------------\[ cut here \]------------'),
        "vmx": re.compile(r'VMX.*?error', re.IGNORECASE),
        "kvm": re.compile(r'KVM:.*?error', re.IGNORECASE),
    }
    
    def __init__(self):
        self.detected_crashes = []
    
    def analyze_output(self, output: str) -> List[CrashInfo]:
        """Analyze guest output for crash indicators"""
        crashes = []
        
        # Check for panic
        panic_match = self.CRASH_PATTERNS["panic"].search(output)
        if panic_match:
            crashes.append(self._parse_panic(output, panic_match))
        
        # Check for oops
        oops_match = self.CRASH_PATTERNS["oops"].search(output)
        if oops_match:
            crashes.append(self._parse_oops(output, oops_match))
        
        # Check for softlockup
        softlockup_match = self.CRASH_PATTERNS["softlockup"].search(output)
        if softlockup_match:
            crashes.append(self._parse_softlockup(output, softlockup_match))
        
        # Check for general warnings
        if self.CRASH_PATTERNS["warning"].search(output):
            if not any(crash.type in ["oops", "panic", "softlockup"] for crash in crashes):
                crashes.append(self._parse_warning(output))
        
        # Check for VMX/KVM specific errors
        if self.CRASH_PATTERNS["vmx"].search(output) or self.CRASH_PATTERNS["kvm"].search(output):
            crashes.append(self._parse_kvm_error(output))
        
        return crashes
    
    def _parse_panic(self, output: str, match) -> CrashInfo:
        """Parse kernel panic"""
        reason = match.group(1) if match.groups() else "Unknown"
        
        # Extract stack trace
        stack_lines = []
        in_stack = False
        for line in output.split('\n'):
            if "Call Trace:" in line:
                in_stack = True
            elif in_stack and line.strip() and not line.startswith('['):
                if len(stack_lines) < 30:
                    stack_lines.append(line.strip())
                else:
                    break
        
        return CrashInfo(
            type="panic",
            location=reason,
            stack_trace=stack_lines,
            registers=self._extract_registers(output),
            timestamp=time.time()
        )
    
    def _parse_oops(self, output: str, match) -> CrashInfo:
        """Parse kernel Oops"""
        rip_match = re.search(r'RIP: \d+:(.*?)(?:\n|$)', output)
        location = rip_match.group(1) if rip_match else "Unknown"
        
        stack_lines = []
        in_stack = False
        for line in output.split('\n'):
            if "Call Trace:" in line:
                in_stack = True
            elif in_stack and line.strip() and not line.startswith('['):
                if len(stack_lines) < 30:
                    stack_lines.append(line.strip())
                else:
                    break
        
        return CrashInfo(
            type="oops",
            location=location,
            stack_trace=stack_lines,
            registers=self._extract_registers(output),
            timestamp=time.time()
        )
    
    def _parse_softlockup(self, output: str, match) -> CrashInfo:
        """Parse soft lockup"""
        cpu_match = re.search(r'CPU (\d+)', output)
        cpu = cpu_match.group(1) if cpu_match else "Unknown"
        
        return CrashInfo(
            type="softlockup",
            location=f"CPU {cpu}",
            stack_trace=self._extract_stack_trace(output),
            registers={},
            timestamp=time.time()
        )
    
    def _parse_warning(self, output: str) -> CrashInfo:
        """Parse general kernel warning"""
        warning_lines = []
        for line in output.split('\n'):
            if "WARNING:" in line or "BUG:" in line:
                warning_lines.append(line)
                break
        
        return CrashInfo(
            type="warning",
            location=warning_lines[0] if warning_lines else "Unknown warning",
            stack_trace=self._extract_stack_trace(output),
            registers={},
            timestamp=time.time()
        )
    
    def _parse_kvm_error(self, output: str) -> CrashInfo:
        """Parse KVM/VMX specific errors"""
        error_lines = []
        for line in output.split('\n'):
            if any(x in line.lower() for x in ['kvm', 'vmx', 'vmexit']):
                error_lines.append(line)
        
        return CrashInfo(
            type="kvm_error",
            location="KVM/VMX subsystem",
            stack_trace=error_lines[:20],
            registers={},
            timestamp=time.time()
        )
    
    def _extract_registers(self, output: str) -> Dict[str, str]:
        """Extract register values from crash dump"""
        registers = {}
        reg_pattern = re.compile(r'([A-Z]+):\s+([0-9a-fx]+)', re.IGNORECASE)
        
        for match in reg_pattern.finditer(output):
            reg_name = match.group(1)
            reg_value = match.group(2)
            if reg_name in ['RAX', 'RBX', 'RCX', 'RDX', 'RBP', 'RSP', 'RIP', 'RFLAGS']:
                registers[reg_name] = reg_value
        
        return registers
    
    def _extract_stack_trace(self, output: str) -> List[str]:
        """Extract stack trace from output"""
        stack_lines = []
        in_stack = False
        
        for line in output.split('\n'):
            if "Call Trace:" in line:
                in_stack = True
            elif in_stack and line.strip():
                if line.strip().startswith('<') or line.strip().startswith('['):
                    continue
                if len(stack_lines) < 30:
                    stack_lines.append(line.strip())
                else:
                    break
        
        return stack_lines

# ============================================================================
# TEST SUITE
# ============================================================================

class TestSuite:
    def __init__(self):
        self.tests: List[TestCase] = []
        self._register_tests()
    
    def _register_tests(self):
        """Register all test cases"""
        
        self.tests.append(TestCase(
            id=0,
            name="communication_test",
            description="Test basic guest communication",
            category="basic",
            dangerous=False
        ))
        
        self.tests.append(TestCase(
            id=2,
            name="msr_sysenter_fuzz",
            description="Fuzz SYSENTER MSRs",
            category="msr",
            dangerous=False
        ))
        
        self.tests.append(TestCase(
            id=3,
            name="msr_gs_base_fuzz",
            description="Fuzz GS_BASE and KERNEL_GS_BASE",
            category="msr",
            dangerous=False
        ))
        
        self.tests.append(TestCase(
            id=6,
            name="memory_scan",
            description="Scan for shared memory regions",
            category="memory",
            dangerous=False
        ))
        
        self.tests.append(TestCase(
            id=7,
            name="physical_alias_scan",
            description="Scan physical memory for aliasing",
            category="memory",
            dangerous=False
        ))
        
        self.tests.append(TestCase(
            id=9,
            name="cpuid_fuzz",
            description="Fuzz CPUID leaves",
            category="cpu",
            dangerous=False
        ))
        
        self.tests.append(TestCase(
            id=10,
            name="debug_reg_fuzz",
            description="Fuzz debug registers",
            category="debug",
            dangerous=False
        ))
        
        self.tests.append(TestCase(
            id=13,
            name="io_port_fuzz",
            description="Fuzz I/O port accesses",
            category="io",
            dangerous=False
        ))
        
        self.tests.append(TestCase(
            id=14,
            name="interrupt_fuzz",
            description="Fuzz interrupt delivery",
            category="interrupt",
            dangerous=False
        ))
        
    def get_test(self, test_id: int) -> Optional[TestCase]:
        for test in self.tests:
            if test.id == test_id:
                return test
        return None

# ============================================================================
# VM MANAGER
# ============================================================================

class VMInstance:
    def __init__(self, vm_id: int, config: FuzzerConfig):
        self.vm_id = vm_id
        self.config = config
        self.process: Optional[subprocess.Popen] = None
        self.serial_port = config.SERIAL_PORT_BASE + vm_id
        self.monitor_port = config.MONITOR_PORT_BASE + vm_id
        self.ssh_port = config.SSH_PORT_BASE + vm_id
        self.log_file = None
        self.start_time = None
        self.serial_socket = None
        self.overlay = None
        self.boot_messages = ""
        
    def start(self) -> bool:
        """Start VM with kernel/initrd"""
        try:
            # Create temporary overlay image
            self.overlay = f"/tmp/kvmctf_vm{self.vm_id}_overlay.qcow2"
            
            subprocess.run([
                "qemu-img", "create",
                "-f", "qcow2",
                "-b", self.config.VM_IMAGE,
                "-F", "qcow2",
                self.overlay
            ], check=True, capture_output=True)
            
            self.log_file = f"/tmp/kvmctf_vm{self.vm_id}.log"
            
            qemu_cmd = [
                self.config.QEMU_BIN,
                "-enable-kvm",
                "-cpu", "host,+vmx",
                "-m", self.config.VM_MEMORY,
                "-smp", str(self.config.VM_CPUS),
                "-drive", f"file={self.overlay},format=qcow2,if=ide",
                "-kernel", self.config.VM_KERNEL,
                "-initrd", self.config.VM_INITRD,
                "-append", self.config.VM_KERNEL_ARGS,
                "-netdev", f"user,id=net0,hostfwd=tcp::{self.ssh_port}-:22",
                "-device", "virtio-net-pci,netdev=net0",
                "-nographic",
                "-serial", f"tcp:127.0.0.1:{self.serial_port},server,nowait",
                "-monitor", f"tcp:127.0.0.1:{self.monitor_port},server,nowait",
            ]
            
            print(f"[VM {self.vm_id}] Starting with serial port {self.serial_port}")
            
            log_f = open(self.log_file, 'w')
            self.process = subprocess.Popen(
                qemu_cmd,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )
            
            self.start_time = time.time()
            
            # Wait for serial port
            if not self._wait_for_serial(timeout=self.config.VM_BOOT_TIMEOUT):
                return False
            
            if not self._connect_serial():
                return False
            
            # Wait for agent ready
            self._wait_for_agent_ready(timeout=20)
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to start VM {self.vm_id}: {e}")
            return False
    
    def _wait_for_serial(self, timeout: int) -> bool:
        """Wait for serial port to become available"""
        start = time.time()
        while time.time() - start < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect(('127.0.0.1', self.serial_port))
                sock.close()
                return True
            except:
                time.sleep(0.5)
        return False
    
    def _connect_serial(self) -> bool:
        """Connect to serial port"""
        try:
            self.serial_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.serial_socket.settimeout(5)
            self.serial_socket.connect(('127.0.0.1', self.serial_port))
            self.serial_socket.setblocking(False)
            return True
        except Exception as e:
            print(f"[ERROR] Failed to connect to serial: {e}")
            return False
    
    def _wait_for_agent_ready(self, timeout: int) -> bool:
        """Wait for guest agent to signal it's ready"""
        start = time.time()
        ready_markers = ["Guest Fuzzing Agent Started", "Ready to receive test commands"]
        
        while time.time() - start < timeout:
            try:
                data = self.serial_socket.recv(4096)
                if data:
                    decoded = data.decode('utf-8', errors='ignore')
                    self.boot_messages += decoded
                    if any(marker in decoded for marker in ready_markers):
                        return True
            except socket.error:
                time.sleep(0.1)
            except:
                pass
        
        return False
    
    def clear_buffer(self):
        """Clear any pending data in serial buffer"""
        try:
            self.serial_socket.setblocking(False)
            while True:
                data = self.serial_socket.recv(4096)
                if not data:
                    break
        except:
            pass
    
    def send_command(self, command: str) -> bool:
        """Send command to guest via serial"""
        try:
            if not self.serial_socket:
                if not self._connect_serial():
                    return False
            
            self.clear_buffer()
            self.serial_socket.sendall((command + "\n").encode())
            return True
        except Exception as e:
            print(f"[ERROR] Failed to send command: {e}")
            return False
    
    def wait_for_result(self, timeout: int) -> Optional[str]:
        """Wait for result from guest via serial"""
        start_time = time.time()
        collected_data = []
        
        completion_markers = ["TEST_PASSED", "TEST_FAILED", "ESCAPE_DETECTED", "UNKNOWN_COMMAND"]
        
        try:
            self.serial_socket.setblocking(False)
            
            while time.time() - start_time < timeout:
                try:
                    data = self.serial_socket.recv(4096)
                    if data:
                        decoded = data.decode('utf-8', errors='ignore')
                        collected_data.append(decoded)
                        full_output = ''.join(collected_data)
                        
                        if any(marker in full_output for marker in completion_markers):
                            return full_output
                            
                except socket.error:
                    time.sleep(0.05)
                except:
                    pass
                
                time.sleep(0.05)
            
            return ''.join(collected_data) if collected_data else None
            
        except Exception as e:
            print(f"[ERROR] Failed to receive result: {e}")
            return None
    
    def is_alive(self) -> bool:
        """Check if VM is still running"""
        if not self.process:
            return False
        return self.process.poll() is None
    
    def kill(self):
        """Force kill VM"""
        if self.serial_socket:
            try:
                self.serial_socket.close()
            except:
                pass
            self.serial_socket = None
            
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                self.process.wait(timeout=5)
            except:
                try:
                    self.process.kill()
                except:
                    pass
            self.process = None
            
        if self.overlay and os.path.exists(self.overlay):
            try:
                os.remove(self.overlay)
            except:
                pass

# ============================================================================
# FUZZER ENGINE
# ============================================================================

class KVMFuzzer:
    def __init__(self, config: FuzzerConfig):
        self.config = config
        self.test_suite = TestSuite()
        self.results: List[TestResult] = []
        self.escapes: List[EscapeEvent] = []
        self.running = False
        self.vm_pool: List[VMInstance] = []
        self.crash_analyzer = CrashAnalyzer()
        
        Path(config.RESULTS_DIR).mkdir(exist_ok=True)
    
    def parse_test_result(self, output: str, test: TestCase) -> str:
        """Parse the test result from guest output"""
        if not output:
            return "timeout"
        
        output_lower = output.lower()
        
        # Check for escape first
        if "escape" in output_lower:
            return "escape"
        
        # Check for crashes
        crashes = self.crash_analyzer.analyze_output(output)
        if crashes:
            return "crashed"
        
        # Check for explicit test results
        if "test_passed" in output_lower:
            return "passed"
        
        if "test_failed" in output_lower:
            return "failed"
        
        if "unknown_command" in output_lower:
            return "failed"
        
        return "unknown"
    
    def extract_test_output(self, output: str) -> str:
        """Extract relevant test output"""
        lines = output.split('\n')
        test_lines = []
        
        for line in lines:
            # Skip kernel boot messages
            if re.match(r'\[\s*\d+\.\d+\]', line):
                continue
            # Keep test and crash related lines
            if any(x in line for x in ['TEST:', 'Running', 'completed', 'PASSED', 'FAILED', 
                                        'panic', 'oops', 'BUG:', 'WARNING:', 'Call Trace']):
                test_lines.append(line)
        
        return '\n'.join(test_lines) if test_lines else output[-2000:]
    
    def run_test_in_vm(self, test: TestCase) -> TestResult:
        """Run a single test in a fresh VM"""
        print(f"\n{'='*60}")
        print(f"[TEST {test.id}] {test.name}")
        print(f"[TEST {test.id}] {test.description}")
        print(f"{'='*60}")
        
        vm = VMInstance(len(self.vm_pool), self.config)
        self.vm_pool.append(vm)
        
        start_time = time.time()
        result = TestResult(
            test_id=test.id,
            test_name=test.name,
            status="unknown",
            runtime_ms=0
        )
        
        try:
            print(f"[TEST {test.id}] Starting VM...")
            if not vm.start():
                result.status = "failed"
                result.crash_info = CrashInfo(
                    type="startup_failure",
                    location="VM startup",
                    stack_trace=[],
                    registers={},
                    timestamp=time.time()
                )
                return result
            
            time.sleep(1)
            
            cmd = f"TEST:{test.id}"
            print(f"[TEST {test.id}] Sending command: {cmd}")
            if not vm.send_command(cmd):
                result.status = "failed"
                result.crash_info = CrashInfo(
                    type="communication_failure",
                    location="Serial communication",
                    stack_trace=[],
                    registers={},
                    timestamp=time.time()
                )
                vm.kill()
                return result
            
            print(f"[TEST {test.id}] Waiting for result (timeout: {self.config.TEST_TIMEOUT}s)...")
            output = vm.wait_for_result(self.config.TEST_TIMEOUT)
            
            runtime = time.time() - start_time
            result.runtime_ms = int(runtime * 1000)
            
            if output is None:
                if vm.is_alive():
                    result.status = "timeout"
                else:
                    result.status = "crashed"
                    if self._check_host_escape():
                        result.status = "escape"
                        result.escape_details = self._capture_escape_details(test)
                        self._log_escape(test, result)
            else:
                result.guest_log = output
                result.test_output = self.extract_test_output(output)
                
                # Analyze for crashes
                crashes = self.crash_analyzer.analyze_output(output)
                if crashes:
                    result.crash_info = crashes[0]
                    print(f"[TEST {test.id}] Detected crash: {result.crash_info.type}")
                    print(f"[TEST {test.id}] Location: {result.crash_info.location}")
                
                result.status = self.parse_test_result(output, test)
                
                print(f"[TEST {test.id}] Test output:")
                print("-" * 40)
                print(result.test_output[:1000])
                print("-" * 40)
                
                if result.status == "escape":
                    result.escape_details = self._parse_escape_details(output)
                    self._log_escape(test, result)
            
            return result
            
        except Exception as e:
            result.status = "error"
            result.crash_info = CrashInfo(
                type="exception",
                location=str(e),
                stack_trace=[],
                registers={},
                timestamp=time.time()
            )
            print(f"[TEST {test.id}] Error: {e}")
            import traceback
            traceback.print_exc()
            return result
            
        finally:
            vm.kill()
            result.runtime_ms = int((time.time() - start_time) * 1000)
            print(f"[TEST {test.id}] Result: {result.status} ({result.runtime_ms}ms)")
    
    def _check_host_escape(self) -> bool:
        """Check if escape occurred on host"""
        try:
            dmesg = subprocess.run(
                ["dmesg", "-T", "--level=err,crit,alert,emerg"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            recent = dmesg.stdout.split('\n')[-50:]
            for line in recent:
                if any(x in line.lower() for x in ['kvm', 'qemu', 'oops', 'panic', 'vmx']):
                    return True
            return False
        except:
            return False
    
    def _capture_escape_details(self, test: TestCase) -> Dict:
        """Capture escape details"""
        try:
            dmesg = subprocess.run(["dmesg", "-T"], capture_output=True, text=True, timeout=5)
            dmesg_last = '\n'.join(dmesg.stdout.split('\n')[-100:])
        except:
            dmesg_last = "Failed to capture dmesg"
        
        return {
            "test_id": test.id,
            "test_name": test.name,
            "timestamp": datetime.now().isoformat(),
            "dmesg": dmesg_last,
        }
    
    def _parse_escape_details(self, output: str) -> Dict:
        """Parse escape details from output"""
        details = {}
        lines = output.split('\n')
        for line in lines:
            if ':' in line and any(x in line.lower() for x in ['escape', 'crash', 'panic', 'kvm']):
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip().lower().replace(' ', '_')
                    value = parts[1].strip()
                    details[key] = value
        return details
    
    def _log_escape(self, test: TestCase, result: TestResult):
        """Log escape event"""
        escape = EscapeEvent(
            timestamp=datetime.now().isoformat(),
            test_id=test.id,
            test_name=test.name,
            method=result.escape_details.get("method", "unknown"),
            details=result.escape_details or {},
            guest_state=result.test_output,
            crash_info=result.crash_info
        )
        self.escapes.append(escape)
        
        escape_file = f"{self.config.RESULTS_DIR}/escape_{test.id}_{int(time.time())}.json"
        with open(escape_file, 'w') as f:
            json.dump({
                "timestamp": escape.timestamp,
                "test_id": escape.test_id,
                "test_name": escape.test_name,
                "method": escape.method,
                "details": escape.details,
                "guest_state": escape.guest_state[:5000],
                "crash_info": asdict(escape.crash_info) if escape.crash_info else None
            }, f, indent=2)
        
        print(f"\n{'='*70}")
        print(f"🚨 ESCAPE/CRASH DETECTED 🚨")
        print(f"{'='*70}")
        print(f"Test: {test.name}")
        print(f"Type: {escape.method}")
        if result.crash_info:
            print(f"Crash: {result.crash_info.type} at {result.crash_info.location}")
        print(f"Saved to: {escape_file}")
        print(f"{'='*70}\n")
    
    def run_all_tests(self, skip_dangerous: bool = True):
        """Run all tests sequentially"""
        self.running = True
        
        tests = [t for t in self.test_suite.tests if not t.dangerous] if skip_dangerous else self.test_suite.tests
        
        print(f"\n{'='*70}")
        print(f"KVM FUZZER - Google kvmCTF")
        print(f"{'='*70}")
        print(f"VM Image: {self.config.VM_IMAGE}")
        print(f"Total tests: {len(tests)}")
        print(f"Results dir: {self.config.RESULTS_DIR}")
        print(f"{'='*70}\n")
        
        start_time = time.time()
        
        for i, test in enumerate(tests):
            if not self.running:
                break
            
            print(f"\n[Progress: {i+1}/{len(tests)}]")
            
            result = self.run_test_in_vm(test)
            self.results.append(result)
            self._save_results()
            
            time.sleep(self.config.COOLDOWN_MS / 1000.0)
        
        total_time = time.time() - start_time
        
        print(f"\n{'='*70}")
        print(f"FUZZING COMPLETE")
        print(f"{'='*70}")
        print(f"Total runtime: {total_time:.1f}s")
        print(f"Tests run: {len(self.results)}")
        print(f"Passed: {sum(1 for r in self.results if r.status == 'passed')}")
        print(f"Failed: {sum(1 for r in self.results if r.status == 'failed')}")
        print(f"Crashed: {sum(1 for r in self.results if r.status == 'crashed')}")
        print(f"Timeouts: {sum(1 for r in self.results if r.status == 'timeout')}")
        print(f"Escapes: {len(self.escapes)}")
        print(f"{'='*70}\n")
        
        self._save_results()
    
    def _save_results(self):
        """Save results with crash info"""
        timestamp = int(time.time())
        results_file = f"{self.config.RESULTS_DIR}/results_{timestamp}.json"
        summary_file = f"{self.config.RESULTS_DIR}/summary_{timestamp}.txt"
        
        # Convert results to dict with crash info
        results_dict = []
        for r in self.results:
            r_dict = {
                "test_id": r.test_id,
                "test_name": r.test_name,
                "status": r.status,
                "runtime_ms": r.runtime_ms,
                "guest_log": r.guest_log[:2000] if r.guest_log else "",
                "test_output": r.test_output[:1000] if r.test_output else ""
            }
            if r.crash_info:
                r_dict["crash_info"] = asdict(r.crash_info)
            if r.escape_details:
                r_dict["escape_details"] = r.escape_details
            results_dict.append(r_dict)
        
        with open(results_file, 'w') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "results": results_dict,
                "escapes": [asdict(e) for e in self.escapes],
                "config": {
                    "VM_IMAGE": self.config.VM_IMAGE,
                    "VM_KERNEL": self.config.VM_KERNEL,
                    "VM_INITRD": self.config.VM_INITRD,
                    "TEST_TIMEOUT": self.config.TEST_TIMEOUT
                }
            }, f, indent=2)
        
        with open(summary_file, 'w') as f:
            f.write(f"KVM Fuzzer Results - {datetime.now().isoformat()}\n")
            f.write("="*70 + "\n")
            f.write(f"Total tests: {len(self.results)}\n")
            f.write(f"Passed: {sum(1 for r in self.results if r.status == 'passed')}\n")
            f.write(f"Failed: {sum(1 for r in self.results if r.status == 'failed')}\n")
            f.write(f"Crashed: {sum(1 for r in self.results if r.status == 'crashed')}\n")
            f.write(f"Timeouts: {sum(1 for r in self.results if r.status == 'timeout')}\n")
            f.write(f"Escapes: {len(self.escapes)}\n")
            f.write("="*70 + "\n\n")
            
            if self.escapes:
                f.write("ESCAPE EVENTS:\n")
                for e in self.escapes:
                    f.write(f"  - {e.test_name}: {e.method}\n")
            
            f.write("\nCRASH SUMMARY:\n")
            for r in self.results:
                if r.crash_info:
                    f.write(f"  Test {r.test_id} ({r.test_name}): {r.crash_info.type} - {r.crash_info.location}\n")
        
        print(f"[INFO] Results saved to {results_file}")
        print(f"[INFO] Summary saved to {summary_file}")
    
    def stop(self):
        """Stop fuzzing"""
        self.running = False
        for vm in self.vm_pool:
            vm.kill()

# ============================================================================
# MAIN
# ============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="KVM 0-day Fuzzer for Google kvmCTF")
    parser.add_argument("--vm-image", default=FuzzerConfig.VM_IMAGE)
    parser.add_argument("--kernel", default=FuzzerConfig.VM_KERNEL)
    parser.add_argument("--initrd", default=FuzzerConfig.VM_INITRD)
    parser.add_argument("--include-dangerous", action="store_true")
    parser.add_argument("--test-id", type=int)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--max-vms", type=int, default=1)
    
    args = parser.parse_args()
    
    config = FuzzerConfig(
        VM_IMAGE=args.vm_image,
        VM_KERNEL=args.kernel,
        VM_INITRD=args.initrd,
        TEST_TIMEOUT=args.timeout,
        MAX_CONCURRENT_VMS=args.max_vms
    )
    
    # Check prerequisites
    for path in [config.VM_IMAGE, config.VM_KERNEL, config.VM_INITRD, config.QEMU_BIN]:
        if not os.path.exists(path):
            print(f"[ERROR] Required file not found: {path}")
            sys.exit(1)
    
    fuzzer = KVMFuzzer(config)
    
    def signal_handler(sig, frame):
        print("\n[INFO] Stopping fuzzer...")
        fuzzer.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        if args.test_id is not None:
            test = fuzzer.test_suite.get_test(args.test_id)
            if test:
                result = fuzzer.run_test_in_vm(test)
                fuzzer.results.append(result)
                fuzzer._save_results()
            else:
                print(f"[ERROR] Test ID {args.test_id} not found")
        else:
            fuzzer.run_all_tests(skip_dangerous=not args.include_dangerous)
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user")
        fuzzer.stop()

if __name__ == "__main__":
    main()
