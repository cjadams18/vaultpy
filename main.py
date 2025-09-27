from textual import on
from textual.app import App
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, ListItem, ListView

from vaultpy.db import authenticate_user, create_user
from vaultpy.vault import Vault


class RegisterScreen(Screen):
    def compose(self):
        yield Header()
        yield Label("Register")
        yield Input(placeholder="Username", id="username_input")
        yield Input(placeholder="Password", password=True, id="password_input")
        yield Input(
            placeholder="Confirm Password", password=True, id="confirm_password_input"
        )
        yield Button("Register", id="register", variant="primary")
        yield Label("", id="login_status_label")
        yield Footer()

    @on(Button.Pressed, "#register")
    def handle_register(self):
        username_input = self.query_one("#username_input", Input)
        password_input = self.query_one("#password_input", Input)
        confirm_password_input = self.query_one("#confirm_password_input", Input)
        status_label = self.query_one("#login_status_label", Label)

        if password_input.value != confirm_password_input.value:
            status_label.update("[b red]Passwords do not match[/]")
            return

        result = create_user(username_input.value, password_input.value)
        if not result:
            status_label.update(
                f"[b red]Username '{username_input.value}' already exists[/]"
            )
            return

        # TODO need to return vault path on success for create user
        vault = Vault(f"{username_input.value}.vault")
        try:
            vault.load(password_input.value)
        except Exception as e:
            status_label.update(f"[b red]{e}[/]")
            return

        # Clear fields
        username_input.clear()
        password_input.clear()
        confirm_password_input.clear()
        status_label.update("")

        vault_screen = self.app.SCREENS["vault"](vault)
        self.app.switch_screen(vault_screen)


class LoginScreen(Screen):
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
            status_label.update("[b red]Invalid username or password.[/]")
            return

        vault = Vault(vault_path)
        try:
            vault.load(password_input.value)
        except Exception as e:
            status_label.update(f"[b red]{e}[/]")
            return

        # Clear fields
        username_input.clear()
        password_input.clear()
        status_label.update("")

        vault_screen = self.app.SCREENS["vault"](vault)
        self.app.switch_screen(vault_screen)

    @on(Button.Pressed, "#register")
    def handle_register(self):
        self.app.switch_screen(RegisterScreen())


class VaultScreen(Screen):
    BINDINGS = [("l", "logout", "Logout")]

    def __init__(self, vault: Vault, **kwargs):
        super().__init__(**kwargs)
        self.vault = vault

    def compose(self):
        yield Header()
        yield Label("Passwords")
        yield Label(self.vault.data.__str__())
        yield ListView(
            ListItem(Label("chris")),
            ListItem(Label("james")),
            ListItem(Label("adams")),
        )
        yield Footer()

    def action_logout(self):
        self.app.switch_screen(LoginScreen())


class VaultPy(App):
    CSS_PATH = "main.tcss"
    SCREENS = {"login": LoginScreen, "register": RegisterScreen, "vault": VaultScreen}
    BINDINGS = [
        ("d", "toggle_dark", "Toggle dark mode"),
        ("q", "quit", "Quit the app"),
    ]

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
