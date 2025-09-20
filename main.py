from dotenv import load_dotenv
from textual.app import App
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import Button, Footer, Header, Input, Label, ListView

import vaultpy.db as db
from vaultpy.logger import logger

load_dotenv()
db.setup_database()


class VaultList(ListView):
    def compose(self):
        yield Label("Passwords")


class Login(VerticalScroll):
    def compose(self):
        yield Label("Sign In")
        yield Input("Username")
        yield Input("Password")
        yield Horizontal(
            Button("Login", id="login", variant="success"),
            Button("Register", id="register", variant="primary"),
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "login":
            logger.info("attempting login...")
            vault_name = db.authenticate_user("cjadams18", "helloworld")
            logger.info(vault_name)

            result = self.query("Login")
            if result:
                self.remove(result)


class VaultPy(App):
    BINDINGS = [("d", "toggle_dark", "Toggle dark mode"), ("q", "quit", "Quit the app")]

    def compose(self):
        yield Header()
        yield Login()
        yield Footer()

    def action_toggle_dark(self):
        self.theme = (
            "textual-dark" if self.theme == "textual-light" else "textual-light"
        )

    def action_quit(self):
        self.exit()


if __name__ == "__main__":
    app = VaultPy()
    app.run()
