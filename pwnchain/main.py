import os
import tempfile
import atexit
import readline
from pwn import *
from rich.console import Console
from rich.panel import Panel
from rich.columns import Columns
from rich.table import Table
from rich.theme import Theme
from rich.text import Text

# --- ASCII Art Banner ---
BANNER = """
██████╗ ██╗    ██╗███╗   ██╗██╗  ██╗ ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗
██╔══██╗██║    ██║████╗  ██║██║  ██║██╔════╝██║  ██║██╔══██╗██║████╗  ██║
██████╔╝██║ █╗ ██║██╔██╗ ██║███████║██║     ███████║███████║██║██╔██╗ ██║
██╔═══╝ ██║███╗██║██║╚██╗██║██╔══██║██║     ██╔══██║██╔══██║██║██║╚██╗██║
██║     ╚███╔███╔╝██║ ╚████║██║  ██║╚██████╗██║  ██║██║  ██║██║██║ ╚████║
╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
A Modern CLI for Binary Analysis & Exploitation, powered by Gemini.
"""

# --- Custom Theme ---
custom_theme = Theme({
    "info": "dim cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "prompt": "bold cyan",
    "address": "bold magenta",
    "path": "bold blue",
    "panel_border": "dim blue"
})


class PwnChainCLI:
    """A pwndbg-style CLI for binary analysis."""

    def __init__(self):
        self._current_ssh = None
        self._current_elf = None
        self._current_process = None
        self._current_gdb = None
        self.console = Console(theme=custom_theme)
        context.log_level = 'error'

    def _display_context(self):
        if not self._current_gdb or not self._current_process or not self._current_process.is_alive():
            return
        
        try:
            regs_table = Table(title="Registers", show_header=False, box=None, padding=(0, 1))
            regs_table.add_column("Register", style="cyan")
            regs_table.add_column("Value", style="address")
            regs = self._current_gdb.execute("info registers", to_string=True).splitlines()
            for reg_line in regs:
                parts = reg_line.split()
                if len(parts) >= 2:
                    regs_table.add_row(parts[0], parts[1])
            
            disassembly_text = Text.from_ansi(self._current_gdb.execute("x/10i $pc", to_string=True))
            disasm_panel = Panel(disassembly_text, title="Disassembly", border_style="green", expand=True)

            stack_text = Text.from_ansi(self._current_gdb.execute("x/16xg $rsp", to_string=True))
            stack_panel = Panel(stack_text, title="Stack", border_style="yellow", expand=True)

            self.console.print(Panel(Columns([disasm_panel, stack_panel, regs_table]), border_style="panel_border", title="GDB Context"))
        except Exception as e:
            self.console.print(f"[error]Error updating context: {e}[/error]")

    def handle_command(self, command_str):
        parts = command_str.split()
        if not parts: return
        cmd = parts[0]
        args = parts[1:]
        
        handler = getattr(self, f"_cmd_{cmd}", self._cmd_unknown)
        handler(args)

    def _cmd_unknown(self, args):
        self.console.print(f"[error]Unknown command.[/error]")

    def _cmd_help(self, args):
        help_text = """
[bold]Available Commands:[/bold]
  - [cyan]help[/cyan]: Show this help message.
  - [cyan]exit[/cyan]: Exit the application.
  - [cyan]connect[/cyan] [dim]<user@host[:port]>[/dim]: Connect to a remote host via SSH.
  - [cyan]disconnect[/cyan]: Disconnect from the remote host.
  - [cyan]upload[/cyan] [dim]<local> <remote>[/dim]: Upload a file or folder to the remote host.
  - [cyan]load[/cyan] [dim]<path>[/dim]: Load a binary for analysis (local or remote path).
  - [cyan]run[/cyan] [dim][args...][/dim]: Run the loaded binary.
  - [cyan]gdb[/cyan]: Attach GDB to the running process.
  - [cyan]gdb_cmd[/cyan] [dim]<gdb_command>[/dim]: Execute a raw GDB command.
  - [cyan]c, cont, continue[/cyan]: Continue execution in GDB.
  - [cyan]n, next[/cyan]: Step over next instruction in GDB.
  - [cyan]s, si, step, stepi[/cyan]: Step into next instruction in GDB.
  - [cyan]b, break[/cyan] [dim]<target>[/dim]: Set a breakpoint in GDB.
  - [cyan]exploit[/cyan] [dim][filename][/dim]: Generate a pwntools exploit template.
"""
        self.console.print(Panel(help_text, title="Help", border_style="panel_border"))

    def _cmd_load(self, args):
        if not args:
            self.console.print("[error]Usage: load <file_path>[/error]")
            return
        
        remote_file_path = args[0]
        
        try:
            if self._current_ssh:
                with self.console.status(f"Downloading {remote_file_path}...", spinner="dots"):
                    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                        self._current_ssh.download(remote_file_path, tmp_file.name)
                        local_file_path = tmp_file.name
                atexit.register(os.remove, local_file_path)
                self.console.print(f"[success]Downloaded to temporary file: [path]{local_file_path}[/path][/success]")
            else:
                local_file_path = remote_file_path
                if not os.path.exists(local_file_path):
                    self.console.print(f"[error]Local file not found: [path]{local_file_path}[/path][/error]")
                    return

            self._current_elf = elf = ELF(local_file_path)
            self.console.print(f"[*] Loaded binary: [path]{remote_file_path}[/path]")
            self._run_ai_analysis(elf)

        except Exception as e:
            self.console.print(f"[error]Failed to analyze binary: {e}[/error]")

    def _run_ai_analysis(self, elf):
        checksec_result = elf.checksec(banner=False)
        self.console.print(Panel(str(checksec_result), title="checksec", border_style="panel_border"))
        
        suggestions = []
        if not checksec_result.get('Canary'):
            suggestions.append("- [warning]Canary disabled:[/warning] Potential for Stack Buffer Overflow.")
        if not checksec_result.get('NX'):
            suggestions.append("- [warning]NX disabled:[/warning] Shellcode injection on the stack/heap is possible.")
        if not checksec_result.get('PIE'):
            suggestions.append("- [info]PIE disabled:[/info] Binary addresses are static, simplifying ROP/ret2libc.")
        
        dangerous_functions = ['gets', 'strcpy', 'sprintf', 'system']
        found_dangerous = [func for func in dangerous_functions if func in elf.symbols or func in elf.plt]
        if found_dangerous:
            suggestions.append(f"- [warning]Dangerous functions found:[/warning] {', '.join(found_dangerous)}. Check their usage.")

        if suggestions:
            self.console.print(Panel("\n".join(suggestions), title="AI Analysis Guide", border_style="panel_border"))
        else:
            self.console.print(Panel("No obvious low-hanging fruit vulnerabilities detected.", title="AI Analysis Guide", border_style="panel_border"))

    def _cmd_connect(self, args):
        if not args:
            self.console.print("[error]Usage: connect user@host[:port][/error]")
            return
        
        try:
            user, host, port = self._parse_ssh_string(args[0])
            with self.console.status(f"Connecting to {user}@{host}:{port}...", spinner="earth"):
                self._current_ssh = ssh(host=host, user=user, port=port)
            self.console.print(f"[success]Connected to [bold]{user}@{host}:{port}[/bold]![/success]")
        except Exception as e:
            self.console.print(f"[error]Connection failed: {e}[/error]")

    def _cmd_disconnect(self, args):
        if self._current_ssh:
            self._current_ssh.close()
            self._current_ssh = None
            self.console.print("[success]Disconnected.[/success]")
        else:
            self.console.print("[info]Not connected.[/info]")

    def _cmd_upload(self, args):
        if not self._current_ssh:
            self.console.print("[error]Not connected. Use 'connect' first.[/error]")
            return
        if len(args) != 2:
            self.console.print("[error]Usage: upload <local_path> <remote_path>[/error]")
            return
        
        local_path, remote_path = args
        if not os.path.exists(local_path):
            self.console.print(f"[error]Local path not found: [path]{local_path}[/path][/error]")
            return
        
        try:
            with self.console.status(f"Uploading '{local_path}'...", spinner="arc"):
                self._current_ssh.upload(local_path, remote_path)
            self.console.print(f"[success]Upload successful.[/success]")
        except Exception as e:
            self.console.print(f"[error]Upload failed: {e}[/error]")

    def _cmd_run(self, args):
        if not self._current_elf:
            self.console.print("[error]No binary loaded.[/error]")
            return
        
        try:
            self.console.print(f"[*] Starting process: [path]{self._current_elf.path}[/path] {' '.join(args)}")
            if self._current_ssh:
                self._current_process = self._current_ssh.process([self._current_elf.path] + args)
            else:
                self._current_process = process([self._current_elf.path] + args)
            self.console.print(f"[success]Process started with PID: {self._current_process.pid}[/success]")
        except Exception as e:
            self.console.print(f"[error]Failed to run process: {e}[/error]")

    def _cmd_gdb(self, args):
        if not self._current_process or not self._current_process.is_alive():
            self.console.print("[error]No running process to attach to.[/error]")
            return
        try:
            self.console.print(f"[*] Attaching GDB to PID {self._current_process.pid}...")
            self._current_gdb = gdb.attach(self._current_process)
            self.console.print("[success]GDB attached.[/success]")
            self._display_context()
        except Exception as e:
            self.console.print(f"[error]Failed to attach GDB: {e}[/error]")

    def _execute_gdb_cmd(self, cmd_func):
        if not self._current_gdb:
            self.console.print("[error]GDB not attached.[/error]")
            return
        try:
            with self.console.status("Executing GDB command...", spinner="line"):
                cmd_func()
            self._display_context()
        except Exception as e:
            self.console.print(f"[error]GDB command failed: {e}[/error]")

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
            self.console.print("[error]Usage: break <address/function_name>[/error]")
            return
        self._execute_gdb_cmd(lambda: self._current_gdb.break_(args[0]))
    def _cmd_break(self, args): self._cmd_b(args)

    def _cmd_gdb_cmd(self, args):
        if not self._current_gdb:
            self.console.print("[error]GDB not attached.[/error]")
            return
        try:
            result = self._current_gdb.execute(" ".join(args), to_string=True)
            self.console.print(result)
        except Exception as e:
            self.console.print(f"[error]GDB command failed: {e}[/error]")

    def _cmd_exploit(self, args):
        if not self._current_elf:
            self.console.print("[error]No binary loaded.[/error]")
            return
        
        exploit_file_name = args[0] if args else "exploit.py"
        connect_host = self._current_ssh.host if self._current_ssh else "127.0.0.1"
        connect_port = self._current_ssh.port if self._current_ssh else 1337

        template = f"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# --- Gemini-generated exploit for: {self._current_elf.path} ---
exe = context.binary = ELF('{self._current_elf.path}')
context.arch = '{self._current_elf.arch}'
# context.log_level = 'debug'

# --- Connection ---
HOST = '{connect_host}'
PORT = {connect_port}

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.REMOTE:
        return connect(HOST, PORT)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# --- GDB Script ---
gdbscript = '''
b main
continue
'''.format(**locals())

# --- AI Suggestions ---
{self._get_ai_suggestions_for_exploit()}

# --- Exploit Logic (EDIT ME!) ---
io = start()

io.interactive()"""
        try:
            with open(exploit_file_name, "w") as f:
                f.write(template)
            self.console.print(f"[success]Generated exploit template: [path]{exploit_file_name}[/path][/success]")
        except Exception as e:
            self.console.print(f"[error]Failed to generate exploit file: {e}[/error]")

    def _get_ai_suggestions_for_exploit(self):
        if not self._current_elf: return ""
        
        checksec_result = self._current_elf.checksec(banner=False)
        suggestions = []
        if not checksec_result.get('Canary'):
            suggestions.append("# - Canary disabled -> Likely Stack Buffer Overflow.")
        if not checksec_result.get('NX'):
            suggestions.append("# - NX disabled -> Shellcode injection is possible.")
        if not checksec_result.get('PIE'):
            suggestions.append("# - PIE disabled -> Static addresses make ROP/ret2libc easier.")
        
        dangerous_functions = ['gets', 'strcpy', 'sprintf', 'system']
        found = [func for func in dangerous_functions if func in self._current_elf.symbols or func in self._current_elf.plt]
        if found:
            suggestions.append(f"# - Dangerous functions found: {', '.join(found)}.")
        
        return "\n".join(suggestions)

    def _parse_ssh_string(self, connect_str):
        user_host, *port_part = connect_str.split(':')
        user, host = user_host.split('@')
        port = int(port_part[0]) if port_part else 22
        return user, host, port

    def run_cli(self):
        self.console.print(Panel(BANNER, border_style="green", expand=False))
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