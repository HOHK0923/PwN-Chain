import os
import tempfile
import atexit
import readline
from pwn import *
from rich.console import Console
from rich.panel import Panel
from rich.columns import Columns
from rich.table import Table

class PwnChainCLI:
    """A pwndbg-style CLI for binary analysis."""

    def __init__(self):
        self._current_ssh = None
        self._current_elf = None
        self._current_process = None
        self._current_gdb = None
        self.console = Console()
        context.log_level = 'error'

    def _display_context(self):
        if not self._current_gdb or not self._current_process or not self._current_process.is_alive():
            return

        try:
            regs_table = Table(title="Registers", show_header=False, box=None)
            regs_table.add_column("Register", style="cyan")
            regs_table.add_column("Value", style="magenta")
            regs = self._current_gdb.execute("info registers", to_string=True).splitlines()
            for reg_line in regs:
                parts = reg_line.split()
                if len(parts) >= 2:
                    regs_table.add_row(parts[0], parts[1])
            
            disassembly = self._current_gdb.execute("x/10i $pc", to_string=True)
            disasm_panel = Panel(disassembly, title="Disassembly", border_style="green")

            stack = self._current_gdb.execute("x/16xg $rsp", to_string=True)
            stack_panel = Panel(stack, title="Stack", border_style="yellow")

            self.console.print(Panel(Columns([disasm_panel, stack_panel, regs_table]), border_style="blue"))
        except Exception as e:
            self.console.print(f"[bold red]Error updating context: {e}[/bold red]")

    def handle_command(self, command_str):
        parts = command_str.split()
        if not parts: return
        cmd = parts[0]
        args = parts[1:]
        
        handler = getattr(self, f"_cmd_{cmd}", self._cmd_unknown)
        handler(args)

    def _cmd_unknown(self, args):
        self.console.print(f"[bold red]Unknown command.[/bold red]")

    def _cmd_help(self, args):
        help_text = """
Available Commands:
  - help: Show this help message.
  - exit: Exit the application.
  - connect <user@host[:port]>: Connect to a remote host via SSH.
  - disconnect: Disconnect from the remote host.
  - upload <local> <remote>: Upload a file or folder to the remote host.
  - load <path>: Load a binary for analysis (local or remote path).
  - run [args...]: Run the loaded binary.
  - gdb: Attach GDB to the running process.
  - gdb_cmd <gdb_command>: Execute a raw GDB command.
  - c, cont, continue: Continue execution in GDB.
  - n, next: Step over next instruction in GDB.
  - s, si, step, stepi: Step into next instruction in GDB.
  - b, break <target>: Set a breakpoint in GDB.
  - exploit [filename]: Generate a pwntools exploit template.
"""
        self.console.print(Panel(help_text, title="Help"))

    def _cmd_load(self, args):
        if not args:
            self.console.print("[bold red]Usage: load <file_path>[/bold red]")
            return
        
        remote_file_path = args[0]
        local_file_path = None
        
        try:
            if self._current_ssh:
                self.console.print(f"[*] Downloading {remote_file_path} from remote...")
                with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                    self._current_ssh.download(remote_file_path, tmp_file.name)
                    local_file_path = tmp_file.name
                atexit.register(os.remove, local_file_path)
                self.console.print(f"[green][SUCCESS][/green] Downloaded to temporary file: {local_file_path}")
            else:
                local_file_path = remote_file_path
                if not os.path.exists(local_file_path):
                    self.console.print(f"[bold red]Local file not found: {local_file_path}[/bold red]")
                    return

            self._current_elf = elf = ELF(local_file_path)
            self.console.print(f"[*] Loaded binary: [cyan]{remote_file_path}[/cyan]")
            self._run_ai_analysis(elf)

        except Exception as e:
            self.console.print(f"[bold red]Failed to analyze binary: {e}[/bold red]")

    def _run_ai_analysis(self, elf):
        checksec_result = elf.checksec(banner=False)
        self.console.print(Panel(str(checksec_result), title="checksec"))
        
        suggestions = []
        if not checksec_result.get('Canary'):
            suggestions.append("- [bold yellow]Canary disabled:[/bold yellow] Potential for Stack Buffer Overflow.")
        if not checksec_result.get('NX'):
            suggestions.append("- [bold yellow]NX disabled:[/bold yellow] Shellcode injection on the stack/heap is possible.")
        if not checksec_result.get('PIE'):
            suggestions.append("- [bold yellow]PIE disabled:[/bold yellow] Binary addresses are static, simplifying ROP/ret2libc.")
        
        dangerous_functions = ['gets', 'strcpy', 'sprintf', 'system']
        found_dangerous = [func for func in dangerous_functions if func in elf.symbols or func in elf.plt]
        if found_dangerous:
            suggestions.append(f"- [bold yellow]Dangerous functions found:[/bold yellow] {', '.join(found_dangerous)}. Check their usage.")

        if suggestions:
            self.console.print(Panel("\n".join(suggestions), title="AI Analysis Guide"))
        else:
            self.console.print(Panel("No obvious low-hanging fruit vulnerabilities detected.", title="AI Analysis Guide"))

    def _cmd_connect(self, args):
        if not args:
            self.console.print("[bold red]Usage: connect user@host[:port][/bold red]")
            return
        
        try:
            user, host, port = self._parse_ssh_string(args[0])
            self.console.print(f"[*] Connecting to {user}@{host}:{port}...")
            self._current_ssh = ssh(host=host, user=user, port=port)
            self.console.print(f"[bold green]Connected![/bold green]")
        except Exception as e:
            self.console.print(f"[bold red]Connection failed: {e}[/bold red]")

    def _cmd_disconnect(self, args):
        if self._current_ssh:
            self._current_ssh.close()
            self._current_ssh = None
            self.console.print("[green]Disconnected.[/green]")
        else:
            self.console.print("Not connected.")

    def _cmd_upload(self, args):
        if not self._current_ssh:
            self.console.print("[bold red]Not connected. Use 'connect' first.[/bold red]")
            return
        if len(args) != 2:
            self.console.print("[bold red]Usage: upload <local_path> <remote_path>[/bold red]")
            return
        
        local_path, remote_path = args
        if not os.path.exists(local_path):
            self.console.print(f"[bold red]Local path not found: {local_path}[/bold red]")
            return
        
        try:
            self.console.print(f"[*] Uploading '{local_path}' to remote '{remote_path}'...")
            self._current_ssh.upload(local_path, remote_path)
            self.console.print(f"[bold green]Upload successful.[/bold green]")
        except Exception as e:
            self.console.print(f"[bold red]Upload failed: {e}[/bold red]")

    def _cmd_run(self, args):
        if not self._current_elf:
            self.console.print("[bold red]No binary loaded.[/bold red]")
            return
        
        try:
            self.console.print(f"[*] Starting process: {self._current_elf.path} {' '.join(args)}")
            if self._current_ssh:
                self._current_process = self._current_ssh.process([self._current_elf.path] + args)
            else:
                self._current_process = process([self._current_elf.path] + args)
            self.console.print(f"[green]Process started with PID: {self._current_process.pid}[/green]")
        except Exception as e:
            self.console.print(f"[bold red]Failed to run process: {e}[/bold red]")

    def _cmd_gdb(self, args):
        if not self._current_process or not self._current_process.is_alive():
            self.console.print("[bold red]No running process to attach to.[/bold red]")
            return
        try:
            self.console.print(f"[*] Attaching GDB to PID {self._current_process.pid}...")
            self._current_gdb = gdb.attach(self._current_process)
            self.console.print("[bold green]GDB attached.[/bold green]")
            self._display_context()
        except Exception as e:
            self.console.print(f"[bold red]Failed to attach GDB: {e}[/bold red]")

    def _execute_gdb_cmd(self, cmd_func):
        if not self._current_gdb:
            self.console.print("[bold red]GDB not attached.[/bold red]")
            return
        try:
            cmd_func()
            self._display_context()
        except Exception as e:
            self.console.print(f"[bold red]GDB command failed: {e}[/bold red]")

    def _cmd_c(self, args): self._execute_gdb_cmd(lambda: self._current_gdb.cont())
    def _cmd_cont(self, args): self._cmd_c(args)
    def _cmd_continue(self, args): self._cmd_c(args)
    
    def _cmd_n(self, args): self._execute_gdb_cmd(lambda: self._current_gdb.next())
    def _cmd_next(self, args): self._cmd_n(args)

    def _cmd_s(self, args): self._execute_gdb_cmd(lambda: self._current_gdb.step())
    def _cmd_si(self, args): self._cmd_s(args)
    def _cmd_step(self, args): self._cmd_s(args)
    def _cmd_stepi(self, args): self._cmd_s(args)

    def _cmd_b(self, args):
        if not args:
            self.console.print("[bold red]Usage: break <address/function_name>[/bold red]")
            return
        self._execute_gdb_cmd(lambda: self._current_gdb.break_(args[0]))
    def _cmd_break(self, args): self._cmd_b(args)

    def _cmd_gdb_cmd(self, args):
        if not self._current_gdb:
            self.console.print("[bold red]GDB not attached.[/bold red]")
            return
        try:
            result = self._current_gdb.execute(" ".join(args), to_string=True)
            self.console.print(result)
        except Exception as e:
            self.console.print(f"[bold red]GDB command failed: {e}[/bold red]")

    def _cmd_exploit(self, args):
        if not self._current_elf:
            self.console.print("[bold red]No binary loaded. Use 'load /path/to/binary' first to get context.[/bold red]")
            return

        exploit_file_name = args[0] if args else "exploit.py"
        connect_host = self._current_ssh.host if self._current_ssh else "127.0.0.1"
        connect_port = self._current_ssh.port if self._current_ssh else 1337

        template = f"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# --- Gemini-generated exploit for: {self._current_elf.path} ---

# For remote debugging, you can use a command like:
# gdbserver :1234 {self._current_elf.path}
# Then, in a separate terminal:
# socat TCP-LISTEN:23946,reuseaddr,fork TCP:localhost:1234 &
# ./venv/bin/PwnChain, then 'gdb localhost:23946'

# --- Setup ---
exe = context.binary = ELF('{self._current_elf.path}')
context.arch = '{self._current_elf.arch}'
# context.log_level = 'debug'

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

# --- AI Suggestions ---
# {self._get_ai_suggestions_for_exploit()}

# --- Exploit Logic (EDIT ME!) ---
io = start()

# Example: Buffer Overflow (if Canary is disabled)
# from pwnlib.util.cyclic import cyclic, cyclic_find
# offset = cyclic_find(b'...') # Find offset by running in GDB: `cyclic 200`, `run`, `p $rsp`
# payload = flat(
#     b'A' * offset,
#     p64(0xdeadbeef) # Return address (e.g., exe.sym.win_function)
# )

# Send the payload
# io.sendline(payload)

io.interactive()
"""
        
        try:
            with open(exploit_file_name, "w") as f:
                f.write(template)

            self.console.print(f"[bold green][SUCCESS][/bold green] Generated exploit template: [cyan]{exploit_file_name}[/cyan]")
            self.console.print("[*] Remember to fill in your exploit logic.")
            self.console.print(f"[*] Run with: `python3 {exploit_file_name} REMOTE` or `python3 {exploit_file_name} GDB`")
        except Exception as e:
            self.console.print(f"[bold red]Failed to generate exploit file: {e}[/bold red]")

    def _get_ai_suggestions_for_exploit(self):
        if not self._current_elf:
            return ""
        
        checksec_result = self._current_elf.checksec(banner=False)
        suggestions = []
        if not checksec_result.get('Canary'):
            suggestions.append("# - Canary disabled: Likely vulnerable to Stack Buffer Overflow.")
        if not checksec_result.get('NX'):
            suggestions.append("# - NX disabled: Shellcode injection is a possible vector.")
        if not checksec_result.get('PIE'):
            suggestions.append("# - PIE disabled: Static addresses make ROP/ret2libc easier.")
        
        dangerous_functions = ['gets', 'strcpy', 'sprintf', 'system']
        found_dangerous = [func for func in dangerous_functions if func in self._current_elf.symbols or func in self._current_elf.plt]
        if found_dangerous:
            suggestions.append(f"# - Dangerous functions found: {', '.join(found_dangerous)}.")
        
        return "\n".join(suggestions)


    def _parse_ssh_string(self, connect_str):
        user_host, *port_part = connect_str.split(':')
        user, host = user_host.split('@')
        port = int(port_part[0]) if port_part else 22
        return user, host, port

    def run_cli(self):
        self.console.print("[bold green]Welcome to PwnChain CLI! (pwndbg-style)[/bold green]")
        self.console.print("Type 'help' for a list of commands.")
        while True:
            try:
                command = input("pwnchain> ").strip()
                if not command: continue
                if command == "exit": break
                self.handle_command(command)
            except KeyboardInterrupt:
                self.console.print("\n(To exit, type 'exit')")
            except EOFError:
                break
        self.console.print("[bold green]Goodbye![/bold green]")

def main():
    cli = PwnChainCLI()
    cli.run_cli()
