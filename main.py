import customtkinter as ctk
from PIL import Image, ImageTk, ImageFilter
from tkinter import messagebox
import cv2
import threading
import time
import platform

def is_windows_11():
    try:
        return int(platform.version().split(".")[2]) >= 22000
    except Exception:
        return False

# === Splash Overlay Within GUI Using Video ===
def play_splash_in_gui(root, video_path, on_finish):
    splash_overlay = ctk.CTkFrame(root, width=720, height=180, corner_radius=0, fg_color="black")
    splash_overlay.place(x=0, y=0, relwidth=1, relheight=1)

    label = ctk.CTkLabel(splash_overlay, text="")
    label.pack(expand=True, fill="both")

    cap = cv2.VideoCapture(video_path)

    def update_frame():
        ret, frame = cap.read()
        if not ret:
            cap.release()
            fade_out()
            return

        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        img = Image.fromarray(frame)
        img = img.resize((720, 180), Image.LANCZOS)
        imgtk = ImageTk.PhotoImage(image=img)
        label.imgtk = imgtk
        label.configure(image=imgtk)
        splash_overlay.after(25, update_frame)

    def fade_out():
        try:
            splash_overlay.attributes("-alpha", 1.0)
            for alpha in range(10, -1, -1):
                splash_overlay.attributes("-alpha", alpha / 10)
                splash_overlay.update()
                time.sleep(0.05)
        except:
            pass
        splash_overlay.destroy()
        on_finish()

    try:
        splash_overlay.attributes("-alpha", 1.0)
    except:
        pass

    update_frame()

# === Main GUI ===
def launch_gui():
    root = ctk.CTk()
    root.geometry("720x550")
    root.wm_iconbitmap("themes/orange.ico")
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("themes/orange.json")

    app = OrangeBoosterApp(root)
    play_splash_in_gui(root, "lv_0_20250411225908.mp4", lambda: None)

    root.mainloop()

class OrangeBoosterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("OrangeBooster")
        self.root.geometry("720x550")
        root.minsize(570, 650)

        content_wrapper = ctk.CTkFrame(root, fg_color="transparent")
        content_wrapper.pack(fill="both", expand=True)

        header_frame = ctk.CTkFrame(content_wrapper, fg_color="transparent")
        header_frame.pack(pady=20, anchor="n")

        orange_img = Image.open("themes/orange.png").resize((64, 64), Image.Resampling.LANCZOS)
        orange_photo = ctk.CTkImage(light_image=orange_img, dark_image=orange_img, size=(64, 64))

        icon_label = ctk.CTkLabel(header_frame, image=orange_photo, text="")
        icon_label.image = orange_photo
        icon_label.pack(side="left", padx=10)

        title_label = ctk.CTkLabel(header_frame, text="OrangBooster", font=("Comic Sans MS", 28, "bold"))
        title_label.pack(side="left")

        self.tabs = {
            "Browser": ["Brave Browser", "Ungoogled Chromium", "Arc Browser"],
            "Updates & About": [],
            "Booster": [
                "Optimize Mouse",
                "Optimize General Tools and Games",
                "Optimize Internet Usage also ping and reduce telemetry",
                "Optimize Services and reduce RAM usage",
                "Uninstall bloatware and delete Edge, OneDrive, Windows UWP",
                "Optimize Windows Settings",
                "Make Everything In list"
            ],
            "Tasks": [
                "Disable Copilot AI",
                "Disable Cortana",
                "Disable Nagle Algorithm For Minecraft",
                "Set Windows To Dark Mode",
                "Disable Bing Search in Start Menu",
                "Set Classic Right-Click Menu",
                "Disable Ads In Windows",
                "Disable BitLocker Encription",
                "Set taskbar to left on Windows 11",
                "Disable Sticky Keys"
            ]
        }

        self.tab_frame = ctk.CTkFrame(content_wrapper)
        self.tab_frame.pack(pady=10)

        self.tab_buttons = {}
        for idx, name in enumerate(self.tabs):
            btn = ctk.CTkButton(
                self.tab_frame, text=name, width=120,
                fg_color="#333333", text_color="#ffffff",
                command=lambda n=name: self.show_tab(n)
            )
            btn.grid(row=0, column=idx, padx=5)
            self.tab_buttons[name] = btn

        self.options_frame = ctk.CTkFrame(content_wrapper)
        self.options_frame.pack(padx=40, pady=30)

        self.toggle_vars = {}
        self.show_tab("Updates & About")

    def show_tab(self, tab_name):
        for name, btn in self.tab_buttons.items():
            if name == tab_name:
                btn.configure(fg_color="#ff7f00", text_color="#000000")
            else:
                btn.configure(fg_color="#333333", text_color="#ffffff")

        for widget in self.options_frame.winfo_children():
            widget.destroy()

        if tab_name == "Browser":
            self.options_frame.grid_columnconfigure((0, 1, 2), weight=1, uniform="browser")

        self.toggle_vars = {}

        if tab_name == "Updates & About":
            import platform
            import getpass

            sys_info = [
                "OrangBooster v2.0",
                "InterJava Studio",
                "Designed By Vakarux",
                "Codeded by adasjusk",
                "",
                "About:",
                f"{platform.system()} {'11' if is_windows_11() else '10'} (Build {platform.version()})"
            ]

            for item in sys_info:
                label = ctk.CTkLabel(self.options_frame, text=item, font=("Helvetica", 13))
                label.pack(pady=0, anchor="center")

            update_button = ctk.CTkButton(self.options_frame, text="Check For Updates", width=160)
            update_button.pack(pady=(2, 2))
            return

        for option in self.tabs[tab_name]:
            if tab_name == "Booster" and option == "Make Everything In list":
                ctk.CTkButton(self.options_frame, text=option, command=lambda: messagebox.showinfo("Running", f"Executing: {option}"), width=160, height=24).pack(anchor="w", pady=4, padx=10)
                continue
            if tab_name == "Browser":
                try:
                    img_path = f"themes/{option.lower().replace(' ', '_')}.png"
                    img = Image.open(img_path)
                    img = img.resize((96, 96), Image.LANCZOS)
                    photo = ImageTk.PhotoImage(img)
                    browser_frame = ctk.CTkFrame(self.options_frame, fg_color="transparent")
                    col = self.tabs[tab_name].index(option)
                    browser_frame.grid(row=0, column=col, padx=10, pady=10, sticky="nsew")

                    img_label = ctk.CTkLabel(browser_frame, image=photo, text="", fg_color="transparent")
                    img_label.image = photo
                    img_label.pack(anchor="center")

                    is_recommended = option == "Brave Browser"
                    label_text = option
                    browser_button = ctk.CTkButton(browser_frame, text=label_text, fg_color="#ff7f00", text_color="#000000", hover_color="#ffa733", width=160, height=48, corner_radius=10)
                    browser_button.pack(pady=(8, 4))

                    if is_recommended:
                        recommended_label = ctk.CTkLabel(browser_frame, text="Recommended", font=("Helvetica", 11, "italic"), text_color="#ffaa33")
                        recommended_label.pack(pady=(2, 0))

                except Exception as e:
                    fallback_label = ctk.CTkLabel(self.options_frame, text=option)
                    fallback_label.pack(anchor="w", pady=6, padx=10)
                except:
                    var = ctk.BooleanVar()
                    switch = ctk.CTkSwitch(self.options_frame, text=option, variable=var, onvalue=True, offvalue=False,
                                        state="disabled" if is_disabled else "normal",
                                        fg_color="#2e2e2e" if is_disabled else None,
                                        text_color="#666666" if is_disabled else None)
                    switch.pack(anchor="w", pady=8, padx=10)
                    self.toggle_vars[option] = var
            elif tab_name == "Updates & About":
                import platform
                import psutil
                import socket
                import getpass

                sys_info = [
                    f"System: {platform.system()} {platform.release()}",
                    f"Machine: {platform.machine()}",
                    f"Processor: {platform.processor()}",
                    f"RAM: {round(psutil.virtual_memory().total / (1024 ** 3), 2)} GB",
                    f"User: {getpass.getuser()}",
                    f"Hostname: {socket.gethostname()}"
                ]

                for item in sys_info:
                    label = ctk.CTkLabel(self.options_frame, text=item, font=("Helvetica", 13))
                    label.pack(pady=1, anchor="center")

                version = ctk.CTkLabel(self.options_frame, text="Version: OrangBooster v1.3", font=("Helvetica", 13, "bold"))
                version.pack(pady=(2, 1))

                credits = [
                    "Made by Orangedev Team",
                    "Special thanks to contributors"
                ]

                for credit in credits:
                    label = ctk.CTkLabel(self.options_frame, text=credit, font=("Helvetica", 12, "italic"))
                    label.pack(pady=1, anchor="center")

                    if option == "Make Everything In list":
                      ctk.CTkButton(self.options_frame, text=option, command=lambda: messagebox.showinfo("Running", f"Executing: {option}"), width=220).pack(pady=8)
                    continue
            else:
                import platform
                win11 = is_windows_11()

                win11_only_options = [
                    "Set taskbar to left on Windows 11",
                    "Disable Copilot AI",
                    "Set Classic Right-Click Menu",
                    "Disable BitLocker Encription"
                ]
                win10_only_options = [
                    "Disable Cortana",
                    "Disable Bing Search in Start Menu"
                ]
                is_disabled = (option in win11_only_options and not win11) or (option in win10_only_options and win11)

                is_disabled = (option in win11_only_options and not win11) or (option in win10_only_options and win11)
                var = ctk.BooleanVar()
                switch = ctk.CTkSwitch(self.options_frame, text=option, variable=var, onvalue=True, offvalue=False,
                    state="disabled" if is_disabled else "normal",
                    fg_color="#2e2e2e" if is_disabled else None,
                    text_color="#666666" if is_disabled else None)
                switch.pack(anchor="w", pady=8, padx=10)
                self.toggle_vars[option] = var

if __name__ == "__main__":
    launch_gui()
