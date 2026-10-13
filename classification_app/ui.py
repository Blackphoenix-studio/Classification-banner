import queue
import sqlite3
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

from .classifier import classify_file
from .enforcement import Enforcer
from .levels import COLORS, LABELS, Level
from .netmonitor import NetworkMonitor
from .service_client import ServiceClient
from .store import Store, current_operator
from .verification import verify_downgrade


class BannerApp:
    def __init__(
        self,
        root: tk.Tk,
        store: Store,
        enforcer: Enforcer,
        dry_run: bool,
        service_client: ServiceClient | None = None,
    ):
        self.root = root
        self.store = store
        self.enforcer = enforcer
        self.dry_run = dry_run
        self.service_client = service_client
        if service_client:
            service_status = service_client.status()
            self.current = service_status.level
            self.warning = service_status.enforcement_error or ""
        else:
            self.current = Level(store.current_level())
            self.warning = ""
        self.events: queue.Queue[tuple[str, str]] = queue.Queue()
        self.monitor = NetworkMonitor(store, lambda text: self.events.put(("alert", text)))
        self.monitor_stop = threading.Event()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.enforcement_lock = threading.Lock()
        self.drag_position: tuple[int, int] | None = None

        self.root.overrideredirect(True)
        self.root.attributes("-topmost", True)
        self.root.geometry("1x20+0+0")
        self.label = tk.Label(
            self.root,
            text="",
            fg="black",
            font=("Segoe UI", -10, "bold"),
            padx=5,
        )
        self.label.pack(fill="both", expand=True)
        self.label.bind("<ButtonPress-1>", self._start_drag)
        self.label.bind("<B1-Motion>", self._drag)
        self.label.bind("<Double-Button-1>", self._center)
        self.label.bind("<Button-3>", self._menu)
        self.root.protocol("WM_DELETE_WINDOW", self._exit)
        self._render()
        self.root.after(1000, self._keep_top)
        self.root.after(150, self._drain_events)
        self.monitor_thread.start()
        self._apply_level(self.current, "startup")

    def _render(self) -> None:
        suffix = " [DRY RUN]" if self.dry_run else ""
        if self.warning:
            suffix += " !"
        self.label.configure(
            text=f" {LABELS[self.current]}{suffix} ",
            bg=COLORS[self.current],
        )
        self.root.update_idletasks()
        width = self.label.winfo_reqwidth()+15
        self.root.geometry(f"{width}x18+{self.root.winfo_x()}+{self.root.winfo_y()}")
        self._center()

    def _keep_top(self) -> None:
        if self.root.winfo_exists():
            self.root.attributes("-topmost", True)
            self.root.after(1000, self._keep_top)

    def _center(self, _event: tk.Event | None = None) -> None:
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - self.root.winfo_width()) // 2
        y = (self.root.winfo_screenheight() - self.root.winfo_height()) // 2
        self.root.geometry(f"+{x}+{y}")

    def _start_drag(self, event: tk.Event) -> None:
        self.drag_position = (event.x_root - self.root.winfo_x(), event.y_root - self.root.winfo_y())

    def _drag(self, event: tk.Event) -> None:
        if self.drag_position is not None:
            x = event.x_root - self.drag_position[0]
            y = event.y_root - self.drag_position[1]
            self.root.geometry(f"+{x}+{y}")

    def _menu(self, event: tk.Event) -> None:
        menu = tk.Menu(self.root, tearoff=False)
        for level in Level:
            menu.add_command(
                label=LABELS[level],
                command=lambda selected=level: self._change_level(selected),
            )
        menu.add_separator()
        menu.add_command(label="Classify a file...", command=self._choose_file)
        menu.add_separator()
        menu.add_command(label="Exit", command=self._exit)
        menu.update_idletasks()
        screen_width = self.root.winfo_screenwidth()
        x = max(0, min(event.x_root, screen_width - menu.winfo_reqwidth()))
        y = self.root.winfo_rooty() + self.root.winfo_height()
        self.root.attributes("-topmost", True)
        menu.tk_popup(x, y)

    def _change_level(self, level: Level) -> None:
        if level < self.current:
            if not messagebox.askyesno(
                "Confirm downgrade",
                "Lowering the classification can re-enable wireless or removable storage. Continue?",
                parent=self.root,
            ):
                return
            self.root.attributes("-topmost", False)
            try:
                if not verify_downgrade(self.store, self.current, level):
                    messagebox.showwarning(
                        "Downgrade not authorized",
                        "Windows Hello verification was not approved. The classification was not changed.",
                        parent=self.root,
                    )
                    return
            except RuntimeError as error:
                messagebox.showerror(
                    "Verification unavailable",
                    f"Windows Hello verification failed. The classification was not changed.\n\n{error}",
                    parent=self.root,
                )
                return
            finally:
                self.root.attributes("-topmost", True)
        self._apply_level(level, "manual_change")

    def _apply_level(self, level: Level, reason: str) -> None:
        previous = self.current
        try:
            if self.service_client:
                actions = self.service_client.set_level(level, reason)
                self.current = level
                self.warning = ""
                self._render()
                self._show_enforcement_actions(actions)
                return

            self.store.set_current_level(int(level))
            self.current = level
            self.store.audit(
                "classification_change",
                int(level),
                current_operator(),
                {"from": int(previous), "to": int(level), "reason": reason},
            )
            with self.enforcement_lock:
                actions = self.enforcer.reconcile(level)
            self.warning = ""
            self._render()
            self._show_enforcement_actions(actions)
        except Exception as error:
            self.warning = str(error)
            self._render()
            if self.service_client:
                message = (
                    "The service did not confirm the classification change. "
                    "The active classification may be unchanged.\n\n"
                )
            else:
                message = f"The classification is recorded as {LABELS[level]}, but enforcement failed:\n\n"
            messagebox.showerror(
                "Classification enforcement failed",
                f"{message}{error}",
                parent=self.root,
            )

    def _show_enforcement_actions(self, actions: list[str]) -> None:
        if not actions:
            return
        action_text = "\n".join(
            ("WOULD " if self.dry_run else "") + action for action in actions
        )
        self.root.title(action_text)
        if self.dry_run:
            messagebox.showinfo("Dry-run policy preview", action_text, parent=self.root)
        else:
            notices = [
                action
                for action in actions
                if action.startswith("Windows cannot take removable media offline")
            ]
            if notices:
                messagebox.showwarning(
                    "Removable USB media",
                    "\n".join(notices),
                    parent=self.root,
                )

    def _choose_file(self) -> None:
        filename = filedialog.askopenfilename(parent=self.root)
        if not filename:
            return
        try:
            result = classify_file(filename, self.store)
            self.store.audit(
                "file_classified",
                int(result.level),
                current_operator(),
                {"path": result.path, "sha256": result.sha256, "evidence": result.evidence},
            )
            target = max(self.current, result.level)
            self._apply_level(target, f"file:{result.path}")
            messagebox.showinfo(
                "File classification",
                f"{LABELS[result.level]}\n{result.path}\nEvidence: {', '.join(result.evidence)}",
                parent=self.root,
            )
        except Exception as error:
            messagebox.showerror("Could not classify file", str(error), parent=self.root)

    def _monitor_loop(self) -> None:
        while not self.monitor_stop.is_set():
            try:
                self.monitor.poll()
            except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
                self.events.put(("error", str(error)))
            if self.service_client:
                try:
                    service_status = self.service_client.status()
                    level = service_status.level
                    if level != self.current:
                        self.events.put(("level", str(int(level))))
                    if service_status.enforcement_error:
                        self.events.put(("enforcement_error", service_status.enforcement_error))
                    else:
                        self.events.put(("enforcement_ok", ""))
                except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
                    self.events.put(("enforcement_error", str(error)))
            else:
                try:
                    level = Level(self.store.current_level())
                    with self.enforcement_lock:
                        self.enforcer.reconcile(level)
                    self.events.put(("enforcement_ok", ""))
                except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
                    self.events.put(("enforcement_error", str(error)))
            self.monitor_stop.wait(15)

    def _drain_events(self) -> None:
        while True:
            try:
                kind, text = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "alert":
                self.root.bell()
                messagebox.showwarning("Network monitor alert", text, parent=self.root)
            elif kind == "enforcement_ok":
                if self.root.title().startswith("Enforcement error:"):
                    self.warning = ""
                    self._render()
                    self.root.title("")
            elif kind == "enforcement_error":
                self.warning = text
                self._render()
                self.root.title(f"Enforcement error: {text}")
            elif kind == "level":
                self.current = Level(int(text))
                self.warning = ""
                self._render()
            else:
                self.warning = text
                self._render()
                self.root.title(f"Network monitoring error: {text}")
        if self.root.winfo_exists():
            self.root.after(150, self._drain_events)

    def _exit(self) -> None:
        if (
            not self.service_client
            and not self.dry_run
            and self.current >= Level.CONFIDENTIAL
        ):
            messagebox.showwarning(
                "Enforcement is active",
                "Lower the classification to UNCLASS before exiting. This desktop-only enforcement can be terminated externally.",
                parent=self.root,
            )
            return
        self.monitor_stop.set()
        self.store.audit("application_exit", int(self.current), current_operator(), {})
        self.root.destroy()
