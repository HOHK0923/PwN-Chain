import os
import tempfile
import atexit
import asyncio # For Textual async
from pwn import *

from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import Header, Footer, Input, RichLog

class PwnChainApp(App):
    """A TUI for binary analysis."""

    CSS_PATH = "main.css"
    BINDINGS = [
        ("d", "toggle_dark", "Toggle dark mode"),
        ("q", "quit", "Quit"),
    ]

    _current_ssh = None # Stores the current SSH connection object
    _current_elf = None # Stores the current ELF object
    _current_process = None # Stores the current running process
    _current_gdb = None # Stores the current GDB process (if attached)

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()
        with Container(id="app-grid"):
            yield RichLog(id="disassembly-view", wrap=True)
            yield RichLog(id="register-view", wrap=True)
            yield RichLog(id="stack-view", wrap=True)
            yield RichLog(id="log-view", wrap=True)
        yield Input(placeholder="Enter command...", id="command-input")
        yield Footer()

    def on_mount(self) -> None:
        """Called when the app is first mounted."""
        self.query_one("#disassembly-view").write("Disassembly")
        self.query_one("#register-view").write("Registers")
        self.query_one("#stack-view").write("Stack")
        self.query_one("#log-view").write("Logs: Enter 'load /path/to/binary' or 'connect user@host:port' to start.")
        self.query_one("#command-input").focus()

    async def on_input_submitted(self, message: Input.Submitted) -> None:
        """Handle submitted commands."""
        command = message.value.strip()
        log_view = self.query_one("#log-view")
        
        if not command:
            return

        log_view.write(f"> {command}")
        parts = command.split()
        cmd, *args = parts

        if cmd == "connect":
            if not args:
                log_view.write("[ERROR] Usage: connect user@host[:port]")
                return
            
            connect_str = args[0]
            try:
                user_host_port = connect_str.split('@')
                if len(user_host_port) != 2:
                    raise ValueError("Invalid format. Use user@host[:port]")
                
                user = user_host_port[0]
                host_port = user_host_port[1].split(':')
                host = host_port[0]
                port = int(host_port[1]) if len(host_port) > 1 else 22

                log_view.write(f"[*] Attempting to connect to {user}@{host}:{port}...")
                self._current_ssh = ssh(host=host, user=user, port=port) # pwntools ssh function
                log_view.write(f"[SUCCESS] Connected to {user}@{host}:{port}. You can now 'load /remote/path/to/binary'.")
            except Exception as e:
                log_view.write(f"[ERROR] Failed to connect: {e}")
                self._current_ssh = None # Ensure connection is cleared on failure

        elif cmd == "load":
            if not args:
                log_view.write("[ERROR] No file path specified.")
                return
            
            remote_file_path = args[0]
            local_file_path = None
            
            try:
                if self._current_ssh:
                    # Download remote file
                    log_view.write(f"[*] Downloading {remote_file_path} from remote...")
                    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                        self._current_ssh.download(remote_file_path, tmp_file.name)
                        local_file_path = tmp_file.name
                    atexit.register(os.remove, local_file_path) # Ensure cleanup on exit
                    log_view.write(f"[SUCCESS] Downloaded to temporary file: {local_file_path}")
                else:
                    local_file_path = remote_file_path
                    if not os.path.exists(local_file_path):
                        log_view.write(f"[ERROR] Local file not found: {local_file_path}")
                        return

                context.log_level = 'error' # Suppress pwntools noisy output
                self._current_elf = elf = ELF(local_file_path) # Store ELF for later
                checksec_result = elf.checksec(banner=False)
                
                log_view.write(f"[*] Loaded binary: {remote_file_path} (local temp: {local_file_path if self._current_ssh else 'N/A'})")
                log_view.write("[*] checksec results:")
                for key, value in checksec_result.items():
                    log_view.write(f"  {key}: {value}")

                # AI-driven analysis guide
                log_view.write("\n[*] AI Analysis Guide:")
                suggestions = []

                # Analyze checksec results
                if not checksec_result.get('Canary'):
                    suggestions.append("- [Exploit Suggestion] Canary not found: Potential for Stack Buffer Overflow without needing to leak canary.")
                if not checksec_result.get('NX'):
                    suggestions.append("- [Exploit Suggestion] NX (No-Execute) disabled: Potential for Shellcode Injection on the stack or heap.")
                if not checksec_result.get('PIE'):
                    suggestions.append("- [Exploit Suggestion] PIE (Position Independent Executable) disabled: Addresses (like main, functions, global variables) are static, simplifying ROP/return-to-libc attacks.")
                
                relro_status = checksec_result.get('RELRO')
                if relro_status in ('Partial', 'No'):
                    suggestions.append(f"- [Exploit Suggestion] RELRO is '{relro_status}': Potential for Global Offset Table (GOT) overwrite attacks.")

                # Scan for dangerous functions
                dangerous_functions = ['gets', 'strcpy', 'sprintf', 'system', 'execve', 'read', 'write']
                found_dangerous = []
                for func in dangerous_functions:
                    if func in elf.symbols or func in elf.plt:
                        found_dangerous.append(func)
                
                if found_dangerous:
                    suggestions.append(f"- [Binary Insight] Potentially dangerous functions identified: {', '.join(found_dangerous)}. Investigate their usage for vulnerabilities.")
                    if 'gets' in found_dangerous:
                        suggestions.append("- [Exploit Suggestion] 'gets' is highly prone to buffer overflows. Look for input buffers where 'gets' is used.")

                if not suggestions:
                    log_view.write("  No obvious vulnerabilities detected by initial static analysis. Focus on logic flaws or less common vulnerabilities.")
                else:
                    for s in suggestions:
                        log_view.write(s)
                log_view.write("") # Add a blank line for readability

                # Display disassembly
                disassembly_view = self.query_one("#disassembly-view")
                disassembly_view.clear()
                disassembly_view.write("[*] Disassembly (main function or entry point):")

                start_addr = None
                if 'main' in elf.symbols:
                    start_addr = elf.symbols['main']
                    log_view.write(f"[*] Found main function at 0x{start_addr:x}")
                elif elf.entry:
                    start_addr = elf.entry
                    log_view.write(f"[*] Using entry point at 0x{start_addr:x}")
                
                if start_addr:
                    # Read some bytes from the start_addr
                    # Adjust size as needed, e.g., 0x100 for 256 bytes
                    code_bytes = elf.read(start_addr, 0x100) 
                    disassembled_code = disasm(code_bytes, arch=elf.arch, vma=start_addr)
                    disassembly_view.write(disassembled_code)
                else:
                    disassembly_view.write("[ERROR] Could not find main function or entry point.")
                
            except Exception as e:
                log_view.write(f"[ERROR] Failed to analyze binary: {e}")
                if self._current_ssh and local_file_path and os.path.exists(local_file_path):
                    os.remove(local_file_path) # Clean up temp file on error
        
        elif cmd == "gdb":
            if not self._current_elf:
                log_view.write("[ERROR] No binary loaded. Use 'load /path/to/binary' first.")
                return
            if not self._current_process:
                log_view.write("[ERROR] No process running. Use 'run' first.")
                return
            
            try:
                log_view.write(f"[*] Attaching GDB to PID {self._current_process.pid}...")
                self._current_gdb = gdb.attach(self._current_process.pid)
                log_view.write("[SUCCESS] GDB attached. Views will update periodically.")
                # Start periodic updates for registers and stack
                self.set_interval(0.5, self._update_debugger_views)
            except Exception as e:
                log_view.write(f"[ERROR] Failed to attach GDB: {e}")
                self._current_gdb = None # Ensure GDB is cleared on failure

        elif cmd == "gdb_cmd":
            if not self._current_gdb:
                log_view.write("[ERROR] GDB not attached. Use 'gdb' command first.")
                return
            if not args:
                log_view.write("[ERROR] Usage: gdb_cmd <command string>")
                return
            gdb_command_str = " ".join(args)
            try:
                output = self._current_gdb.execute(gdb_command_str, to_string=True)
                log_view.write(f"[*] GDB output for '{gdb_command_str}':")
                log_view.write(output)
                self._update_debugger_views() # Update views after GDB command
            except Exception as e:
                log_view.write(f"[ERROR] GDB command failed: {e}")

        elif cmd in ["c", "cont", "continue"]:
            if not self._current_gdb:
                log_view.write("[ERROR] GDB not attached. Use 'gdb' command first.")
                return
            try:
                log_view.write("[*] Continuing process...")
                self._current_gdb.cont()
                log_view.write("[SUCCESS] Process continued.")
                self._update_debugger_views() # Update views after continue
            except Exception as e:
                log_view.write(f"[ERROR] Failed to continue: {e}")

        elif cmd in ["n", "next", "nexti"]:
            if not self._current_gdb:
                log_view.write("[ERROR] GDB not attached. Use 'gdb' command first.")
                return
            try:
                log_view.write("[*] Stepping next instruction...")
                self._current_gdb.next(count=1)
                log_view.write("[SUCCESS] Stepped next instruction.")
                self._update_debugger_views()
            except Exception as e:
                log_view.write(f"[ERROR] Failed to step next: {e}")

        elif cmd in ["s", "si", "step", "stepi"]:
            if not self._current_gdb:
                log_view.write("[ERROR] GDB not attached. Use 'gdb' command first.")
                return
            try:
                log_view.write("[*] Stepping into instruction...")
                self._current_gdb.step(count=1)
                log_view.write("[SUCCESS] Stepped into instruction.")
                self._update_debugger_views()
            except Exception as e:
                log_view.write(f"[ERROR] Failed to step into: {e}")

        elif cmd in ["b", "break"]:
            if not self._current_gdb:
                log_view.write("[ERROR] GDB not attached. Use 'gdb' command first.")
                return
            if not args:
                log_view.write("[ERROR] Usage: break <address/function_name>")
                return
            breakpoint_target = " ".join(args)
            try:
                self._current_gdb.break(breakpoint_target)
                log_view.write(f"[SUCCESS] Breakpoint set at: {breakpoint_target}")
                self._update_debugger_views()
            except Exception as e:
                log_view.write(f"[ERROR] Failed to set breakpoint: {e}")

        elif cmd == "run":
            if not self._current_elf:
                log_view.write("[ERROR] No binary loaded. Use 'load /path/to/binary' first.")
                return
            
            binary_path = self._current_elf.path # Use the path from the loaded ELF

            try:
                log_view.write(f"[*] Running binary: {binary_path} with args: {args}")
                if self._current_ssh:
                    self._current_process = self._current_ssh.process([binary_path] + args)
                    log_view.write("[*] Remote process started. Output will be shown below (limited).")
                else:
                    self._current_process = process([binary_path] + args)
                    log_view.write("[*] Local process started. Output will be shown below (limited).")
                
                # Read initial output from the process
                # This is a very basic way to show output. For full interactivity,
                # we'd need a separate thread/task or Textual's Workers.
                # For now, just read a bit and show.
                output = self._current_process.recv(timeout=1)
                if output:
                    log_view.write("[PROCESS OUTPUT START]")
                    log_view.write(output.decode(errors='ignore'))
                    log_view.write("[PROCESS OUTPUT END]")
                else:
                    log_view.write("[INFO] No immediate output from process.")

            except Exception as e:
                log_view.write(f"[ERROR] Failed to run binary: {e}")

        elif cmd == "upload":
            if not self._current_ssh:
                log_view.write("[ERROR] Not connected to any remote host. Use 'connect user@host[:port]' first.")
                return
            if len(args) != 2:
                log_view.write("[ERROR] Usage: upload <local_path> <remote_path>")
                return
            
            local_path = args[0]
            remote_path = args[1]

            if not os.path.exists(local_path):
                log_view.write(f"[ERROR] Local path not found: {local_path}")
                return
            
            try:
                log_view.write(f"[*] Uploading '{local_path}' to remote '{remote_path}'...")
                self._current_ssh.upload(local_path, remote_path)
                log_view.write(f"[SUCCESS] Uploaded '{local_path}' to '{remote_path}' on remote host.")
            except Exception as e:
                log_view.write(f"[ERROR] Failed to upload: {e}")

        elif cmd == "disconnect":
            if self._current_ssh:
                try:
                    self._current_ssh.close()
                    log_view.write("[SUCCESS] Disconnected from remote host.")
                except Exception as e:
                    log_view.write(f"[ERROR] Error during disconnection: {e}")
                finally:
                    self._current_ssh = None
            else:
                log_view.write("[INFO] Not currently connected to any remote host.")
        
        elif cmd == "exploit":
            if not self._current_elf:
                log_view.write("[ERROR] No binary loaded. Use 'load /path/to/binary' first to get context.")
                return

            exploit_file_name = args[0] if args else "exploit.py"

            # Dynamically determine connection info
            connect_host = self._current_ssh.host if self._current_ssh else "127.0.0.1"
            connect_port = self._current_ssh.port if self._current_ssh else 1337 # Common default

            template = f"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# --- Setup ---
exe = context.binary = ELF('{self._current_elf.path}')
# Set context for architecture and OS (e.g., amd64, i386, arm, linux)
context.arch = '{self._current_elf.arch}'
# context.os = 'linux' # Uncomment if specific OS needed
# context.log_level = 'debug' # 'debug', 'info', 'warn', 'error'

# --- Connection ---
HOST = '{connect_host}'
PORT = {connect_port}

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the target binary remotely'''
    io = connect(HOST, PORT)
    return io

def start(argv=[], *a, **kw):
    '''Start the target process (local or remote)'''
    if args.REMOTE:
        return start_remote(argv, *a, **kw)
    else:
        return start_local(argv, *a, **kw)

# --- GDB Script (optional) ---
gdbscript = '''
b main
continue
'''.format(**locals())

# --- Exploit Logic (EDIT ME!) ---
io = start()

# Example: Buffer Overflow (replace with actual offset)
# offset = 0xXX # Replace with actual offset to return address
# payload = b'A' * offset
# payload += p64(exe.sym.win_function) # Example: return to a 'win' function, or a ROP chain

# Example: Ret2libc (requires libc base address leak)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6') # Adjust libc path for remote, or use local
# pop_rdi = # gadget address
# ret = # gadget address (for stack alignment, if needed)
# payload = b'A' * offset
# payload += p64(pop_rdi)
# payload += p64(libc.sym.str_bin_sh) # Address of "/bin/sh" string in libc
# payload += p64(ret) # for stack alignment
# payload += p64(libc.sym.system) # Address of system() in libc

# Send the payload
# io.sendline(payload) # Use send() or sendline() based on interaction type

# --- Interact ---
io.interactive()

"""
            
            try:
                with open(exploit_file_name, "w") as f:
                    f.write(template)

                log_view.write(f"[SUCCESS] Generated exploit template: {exploit_file_name}")
                log_view.write(f"[*] Remember to update 'HOST', 'PORT', and fill in your exploit logic. ")
                log_view.write(f"[*] Run with: python3 {exploit_file_name} REMOTE (for remote) or python3 {exploit_file_name} GDB (for local with gdb)")
            except Exception as e:
                log_view.write(f"[ERROR] Failed to generate exploit file: {e}")

        else:
            log_view.write(f"[ERROR] Unknown command: {cmd}")
        
        message.input.clear()

    def action_toggle_dark(self) -> None:
        """An action to toggle dark mode."""
        self.dark = not self.dark
    
    def _update_debugger_views(self) -> None:
        if not self._current_gdb or not self._current_process or not self._current_process.is_alive():
            return

        register_view = self.query_one("#register-view")
        stack_view = self.query_one("#stack-view")

        try:
            # Fetch registers
            registers = self._current_gdb.execute("info registers", to_string=True)
            register_view.clear()
            register_view.write("[*] Registers:")
            register_view.write(registers)

            # Fetch stack (e.g., 16 dwords from current RSP)
            # This is simplified; proper stack view needs more logic
            if self._current_gdb.arch.startswith('x86'): # Assuming x86/x86_64 for RSP
                rsp_reg = 'rsp' if self._current_gdb.arch == 'amd64' else 'esp'
                try:
                    # Need to get current context to parse RSP
                    gdb_context = self._current_gdb.execute("info registers", to_string=True)
                    rsp_line = [line for line in gdb_context.splitlines() if rsp_reg in line][0]
                    # Example: rsp            0x7fffffffdfc8    0x7fffffffdfc8
                    rsp_val = int(rsp_line.split()[1], 16)

                    stack_dump = self._current_gdb.execute(f"x/16xg 0x{rsp_val:x}", to_string=True) # 16 qwords (x/xg)
                    stack_view.clear()
                    stack_view.write("[*] Stack (around RSP):")
                    stack_view.write(stack_dump)
                except Exception as e:
                    stack_view.write(f"[ERROR] Could not fetch stack (RSP-based): {e}")
            else:
                stack_view.write("[INFO] Stack view for non-x86 architectures not yet fully implemented.")

        except Exception as e:
            register_view.write(f"[ERROR] GDB update failed: {e}")
            stack_view.write(f"[ERROR] GDB update failed: {e}")


def main():
    app = PwnChainApp()
    app.run()