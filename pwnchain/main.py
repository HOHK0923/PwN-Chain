import os
import tempfile
import atexit
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


        else:
            log_view.write(f"[ERROR] Unknown command: {cmd}")
        
        message.input.clear()

    def action_toggle_dark(self) -> None:
        """An action to toggle dark mode."""
        self.dark = not self.dark

def main():
    app = PwnChainApp()
    app.run()
