import os
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
        self.query_one("#log-view").write("Logs: Enter 'load /path/to/binary' to start.")
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

        if cmd == "load":
            if not args:
                log_view.write("[ERROR] No file path specified.")
                return
            
            file_path = args[0]
            if not os.path.exists(file_path):
                log_view.write(f"[ERROR] File not found: {file_path}")
                return

            try:
                context.log_level = 'error' # Suppress pwntools noisy output
                self._current_elf = elf = ELF(file_path) # Store ELF for later
                checksec_result = elf.checksec(banner=False)
                
                log_view.write(f"[*] Loaded binary: {file_path}")
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

        else:
            log_view.write(f"[ERROR] Unknown command: {cmd}")
        
        message.input.clear()

    def action_toggle_dark(self) -> None:
        """An action to toggle dark mode."""
        self.dark = not self.dark

def main():
    app = PwnChainApp()
    app.run()