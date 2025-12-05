from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import Header, Footer, Static

class PwnChainApp(App):
    """A TUI for binary analysis."""

    CSS_PATH = "main.css"
    BINDINGS = [("d", "toggle_dark", "Toggle dark mode")]

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()
        with Container(id="app-grid"):
            with Container(id="left-column"):
                yield Static("Disassembly", id="disassembly-view")
                yield Static("Stack", id="stack-view")
            with Container(id="right-column"):
                yield Static("Registers", id="register-view")
                yield Static("Logs", id="log-view")
        yield Footer()

    def action_toggle_dark(self) -> None:
        """An action to toggle dark mode."""
        self.dark = not self.dark

if __name__ == "__main__":
    app = PwnChainApp()
    app.run()
