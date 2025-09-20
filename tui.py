from textual.app import App
from textual.containers import VerticalGroup
from textual.widgets import Button, Footer, Header


class Login(VerticalGroup):
    def compose(self):
        yield Button("Login", id="login", variant="success")


class VaultPy(App):
    BINDINGS = [("d", "toggle_dark", "Toggle dark mode"), ("q", "quit", "Quit the app")]

    def compose(self):
        yield Header()
        yield Footer()
        yield Login()

    def action_toggle_dark(self):
        self.theme = (
            "textual-dark" if self.theme == "textual-light" else "textual-light"
        )

    def action_quit(self):
        self.exit()


if __name__ == "__main__":
    app = VaultPy()
    app.run()
