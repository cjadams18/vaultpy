from textual import on
from textual.app import App
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label

from vaultpy.db import authenticate_user
from vaultpy.logger import logger


class Login(Screen):
    def compose(self):
        yield Header()
        yield Label("Sign In")
        yield Input(placeholder="Username", id="username_input")
        yield Input(placeholder="Password", password=True, id="password_input")
        yield Horizontal(
            Button("Login", id="login", variant="success"),
            Button("Register", id="register", variant="primary"),
        )
        yield Label("", id="login_status_label")
        yield Footer()

    @on(Button.Pressed, "#login")
    def handle_login(self):
        username_input = self.query_one("#username_input", Input)
        password_input = self.query_one("#password_input", Input)
        status_label = self.query_one("#login_status_label", Label)

        vault_path = authenticate_user(username_input.value, password_input.value)
        if not vault_path:
            logger.warning("Unable to authenticate user")
            status_label.update("[b red]Invalid username or password.[/]")
        else:
            status_label.update("[b]Login Successful![/]")
            self.app.pop_screen()
            self.app.push_screen("vault")

    @on(Button.Pressed, "#register")
    def handle_register(self):
        logger.info("register pressed")


class Vault(Screen):
    BINDINGS = [("l", "app.pop_screen", "Logout")]

    def compose(self):
        yield Label("Passwords")


class VaultPy(App):
    CSS_PATH = "main.tcss"
    SCREENS = {"login": Login, "vault": Vault}
    BINDINGS = [
        ("d", "toggle_dark", "Toggle dark mode"),
        ("q", "quit", "Quit the app"),
    ]

    def compose(self):
        yield Header()
        yield Footer()

    def on_mount(self):
        self.push_screen("login")

    def action_toggle_dark(self):
        self.theme = (
            "textual-dark" if self.theme == "textual-light" else "textual-light"
        )

    def action_quit(self):
        self.exit()


if __name__ == "__main__":
    app = VaultPy()
    app.run()
