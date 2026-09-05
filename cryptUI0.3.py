#!/usr/bin/env python3
"""
文件加密/解密工具 - 基于块间置换算法
图形界面版本 (tkinter) - 支持亮色/暗色主题、自动检测系统深色模式、实时文件信息、配置持久化
"""

import os
import sys
import random
import hashlib
import struct
import time
import threading
import subprocess
import secrets
import string
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Optional, Any, Callable

print("cryptUI By EJIAOFEN")
credit = "cryptUI By EJIAOFEN | Version: 0.3"

# 用于系统深色模式检测（Windows）
try:
    import winreg
except ImportError:
    winreg = None  # type: Optional[Any]
try:
    import configparser
except ImportError:
    configparser = None  # type: Optional[Any]

# ---------- 配置文件常量 ----------
CONFIG_FILE = ".cryptUI_cfg"
DEFAULT_CONFIG = {
    'dark_mode': 'False',
    'open_folder': 'True',
    'block_size': '1048576',
    'last_input_path': '',
    'last_output_path': '',
    'last_key': '',
    'mode': 'encrypt',
}

# ---------- 核心算法 ----------
def get_block_count(file_size: int, block_size: int) -> int:
    return (file_size + block_size - 1) // block_size

def generate_permutation(num_blocks: int, key: str) -> list:
    seed = int(hashlib.sha256(key.encode()).hexdigest(), 16)
    rng = random.Random(seed)
    perm = list(range(num_blocks))
    rng.shuffle(perm)
    return perm

def format_time(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{int(seconds//60)}m{int(seconds%60)}s"
    return f"{int(seconds//3600)}h{int((seconds%3600)//60)}m{int(seconds%60)}s"

def open_with_default_app(path: str) -> None:
    """用系统默认程序打开文件或文件夹"""
    if not path:
        return
    if not os.path.isabs(path):
        path = os.path.abspath(path)
    if sys.platform == 'win32':
        os.startfile(path)
    elif sys.platform == 'darwin':
        subprocess.Popen(['open', path])
    else:
        subprocess.Popen(['xdg-open', path])

def encrypt_file(input_path: str, output_path: str, key: str, block_size: int,
                 progress_callback: Optional[Callable] = None):
    orig_size = os.path.getsize(input_path)
    num_blocks = get_block_count(orig_size, block_size)
    perm = generate_permutation(num_blocks, key)
    update_interval = max(1, num_blocks // 100) if num_blocks >= 100 else 1

    start_time = time.time()
    total_processed = 0

    with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
        fout.write(struct.pack('<Q', orig_size))
        for idx, block_idx in enumerate(perm):
            fin.seek(block_idx * block_size)
            data = fin.read(block_size)
            if len(data) < block_size:
                data += b'\x00' * (block_size - len(data))
            fout.write(data)
            total_processed += block_size

            if (idx + 1) % update_interval == 0 or idx == num_blocks - 1:
                elapsed = time.time() - start_time
                speed = total_processed / elapsed if elapsed > 0 else 0
                speed_mb = speed / (1024 * 1024)
                if speed > 0:
                    eta_sec = (num_blocks - idx - 1) * block_size / speed
                    eta_str = format_time(eta_sec) if eta_sec > 1 else "<1s"
                else:
                    eta_str = "--:--"
                if progress_callback:
                    progress_callback(100 * (idx + 1) / num_blocks, speed_mb, format_time(elapsed), eta_str)

    total_time = time.time() - start_time
    avg_speed = orig_size / total_time if total_time > 0 else 0
    return total_time, avg_speed / (1024 * 1024)

def decrypt_file(input_path: str, output_path: str, key: str, block_size: int,
                 progress_callback: Optional[Callable] = None):
    with open(input_path, 'rb') as fin:
        header = fin.read(8)
        if len(header) < 8:
            raise ValueError("输入文件格式无效（头部缺失）")
        orig_size = struct.unpack('<Q', header)[0]

    num_blocks = get_block_count(orig_size, block_size)
    last_block_size = orig_size % block_size or block_size

    perm = generate_permutation(num_blocks, key)
    inv_perm = [0] * num_blocks
    for i, v in enumerate(perm):
        inv_perm[v] = i

    update_interval = max(1, num_blocks // 100) if num_blocks >= 100 else 1
    start_time = time.time()
    total_processed = 0

    with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
        fin.seek(8)
        for j in range(num_blocks):
            k = inv_perm[j]
            fin.seek(8 + k * block_size)
            data = fin.read(block_size)
            if len(data) < block_size:
                raise ValueError(f"读取块 {k} 数据不足（期望 {block_size}，实际 {len(data)}）")
            if j == num_blocks - 1:
                data = data[:last_block_size]
                write_size = last_block_size
            else:
                write_size = block_size
            fout.write(data)
            total_processed += write_size

            if (j + 1) % update_interval == 0 or j == num_blocks - 1:
                elapsed = time.time() - start_time
                speed = total_processed / elapsed if elapsed > 0 else 0
                speed_mb = speed / (1024 * 1024)
                if speed > 0:
                    eta_sec = (orig_size - total_processed) / speed
                    eta_str = format_time(eta_sec) if eta_sec > 1 else "<1s"
                else:
                    eta_str = "--:--"
                if progress_callback:
                    progress_callback(100 * (j + 1) / num_blocks, speed_mb, format_time(elapsed), eta_str)

    total_time = time.time() - start_time
    avg_speed = orig_size / total_time if total_time > 0 else 0
    return total_time, avg_speed / (1024 * 1024)


# ---------- 配置读写 ----------
def load_config() -> dict:
    config = DEFAULT_CONFIG.copy()
    if not os.path.exists(CONFIG_FILE):
        return config
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    if key in config:
                        config[key] = value
    except Exception:
        pass
    return config

def save_config(config: dict) -> None:
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            f.write("# 加密工具配置文件\n# 格式: [key] = [value]\n# cryptUI By EJIAOFEN\n\n")
            for key, value in config.items():
                f.write(f"{key} = {value}\n")
    except Exception:
        pass


# ---------- GUI ----------
class CryptoApp:
    def __init__(self, master: tk.Tk) -> None:
        self.root = master
        master.title("File Crypt UI")
        master.geometry("+0+0")
        master.resizable(True, True)

        self.config = load_config()

        # 颜色方案
        self.light_colors = {
            'bg': '#f0f0f0', 'fg': '#000000', 'select_bg': '#0078d7',
            'select_fg': '#ffffff', 'button_bg': '#e1e1e1', 'entry_bg': '#ffffff',
            'progress_bg': '#d0d0d0', 'frame_bg': '#d9d9d9', 'labelframe_bg': '#f0f0f0',
        }
        self.dark_colors = {
            'bg': '#2b2b2b', 'fg': '#ffffff', 'select_bg': '#1e90ff',
            'select_fg': '#ffffff', 'button_bg': '#3c3c3c', 'entry_bg': '#3c3c3c',
            'progress_bg': '#4a4a4a', 'frame_bg': '#3c3c3c', 'labelframe_bg': '#2b2b2b',
        }
        self.current_theme = 'light'

        # 变量
        self.mode_var = tk.StringVar(value=self.config.get('mode', 'encrypt'))
        self.input_path = tk.StringVar(value=self.config.get('last_input_path', ''))
        self.output_path = tk.StringVar(value=self.config.get('last_output_path', ''))
        self.key_var = tk.StringVar(value=self.config.get('last_key', ''))
        self.block_size_var = tk.IntVar(value=int(self.config.get('block_size', '1048576')))
        self.open_folder_var = tk.BooleanVar(value=self.config.get('open_folder', 'True') == 'True')
        self.dark_mode_var = tk.BooleanVar(value=self.config.get('dark_mode', 'False') == 'True')

        self.running = False
        self.thread = None
        self.file_info_var = tk.StringVar(value="")

        # 样式
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.apply_theme('dark' if self.dark_mode_var.get() else 'light')

        self.create_widgets()

        # 首次运行自动检测深色模式
        if not os.path.exists(CONFIG_FILE) and self.detect_system_theme():
            self.dark_mode_var.set(True)
            self.apply_theme('dark')
            self.config['dark_mode'] = 'True'
            save_config(self.config)

        # 绑定配置保存
        for var in (self.mode_var, self.input_path, self.output_path, self.key_var,
                    self.block_size_var, self.open_folder_var, self.dark_mode_var):
            var.trace_add('write', self.on_config_changed)

        self.adjust_window()
        self.input_path.trace_add('write', self.update_file_info)
        master.protocol("WM_DELETE_WINDOW", self.on_closing)

        # ---------- 彩蛋 Label ----------
        self.easter_egg_label = tk.Label(
            self.root,
            text=credit,
            font=("Arial", 12, "bold"),
            fg="gray",
            bg=self.light_colors['bg'] if self.current_theme == 'light' else self.dark_colors['bg']
        )
        self.easter_egg_label.place(x=0, y=491)
        self.easter_egg_label.lift()  # 保持顶层

    def on_config_changed(self, *args: Any) -> None:
        # 安全获取块大小，避免空值错误
        try:
            block_size_val = int(self.block_size_var.get())
        except (ValueError, tk.TclError):
            block_size_val = 1048576  # 默认值
        self.config['mode'] = self.mode_var.get()
        self.config['last_input_path'] = self.input_path.get()
        self.config['last_output_path'] = self.output_path.get()
        self.config['last_key'] = self.key_var.get()
        self.config['block_size'] = str(block_size_val)
        self.config['open_folder'] = 'True' if self.open_folder_var.get() else 'False'
        self.config['dark_mode'] = 'True' if self.dark_mode_var.get() else 'False'
        save_config(self.config)

    def on_closing(self) -> None:
        self.on_config_changed()
        self.root.destroy()

    # ---------- 系统深色模式检测 ----------
    def detect_system_theme(self) -> bool:
        system = sys.platform
        if system == 'win32' and winreg is not None:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                     r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
                value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                winreg.CloseKey(key)
                return value == 0
            except:
                pass
        elif system == 'darwin':
            try:
                result = subprocess.run(['defaults', 'read', '-g', 'AppleInterfaceStyle'],
                                        capture_output=True, text=True, timeout=1)
                return 'Dark' in result.stdout
            except:
                pass
        else:
            if configparser is not None:
                try:
                    config = configparser.ConfigParser()
                    config.read(os.path.expanduser('~/.config/gtk-3.0/settings.ini'))
                    if config.has_section('Settings'):
                        return config.get('Settings', 'gtk-application-prefer-dark-theme', fallback='0') == '1'
                except:
                    pass
            return os.environ.get('GTK_THEME', '').lower().find('dark') != -1
        return False

    # ---------- 文件信息 ----------
    def update_file_info(self, *args: Any) -> None:
        path = self.input_path.get().strip()
        if os.path.isfile(path):
            size = os.path.getsize(path)
            mtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getmtime(path)))
            num_blocks = get_block_count(size, self.block_size_var.get())
            self.file_info_var.set(f"大小: {size:,} 字节 ({size/(1024**2):.2f} MB) | 修改时间: {mtime} | 块数: {num_blocks:,}")
        else:
            self.file_info_var.set("")

    # ---------- 主题 ----------
    def apply_theme(self, theme: str) -> None:
        colors = self.dark_colors if theme == 'dark' else self.light_colors
        self.current_theme = theme
        self.root.configure(bg=colors['bg'])

        style = self.style
        style.configure('TFrame', background=colors['bg'])
        style.configure('TLabel', background=colors['bg'], foreground=colors['fg'])
        style.configure('TButton', background=colors['button_bg'], foreground=colors['fg'])
        style.configure('TEntry', fieldbackground=colors['entry_bg'], foreground=colors['fg'])
        style.configure('TProgressbar', background=colors['select_bg'], troughcolor=colors['progress_bg'])
        style.configure('TLabelframe', background=colors['labelframe_bg'], foreground=colors['fg'])
        style.configure('TLabelframe.Label', background=colors['labelframe_bg'], foreground=colors['fg'])
        style.configure('TRadiobutton', background=colors['bg'], foreground=colors['fg'], selectcolor=colors['select_bg'])
        style.configure('TCheckbutton', background=colors['bg'], foreground=colors['fg'], selectcolor=colors['select_bg'])
        style.configure('TSpinbox', fieldbackground=colors['entry_bg'], foreground=colors['fg'])

        # 取消悬停效果
        for widget in ('TButton', 'TRadiobutton', 'TCheckbutton'):
            style.map(widget,
                      background=[('active', colors['button_bg' if widget == 'TButton' else 'bg'])],
                      foreground=[('active', colors['fg'])])
        for widget in ('TEntry', 'TSpinbox'):
            style.map(widget,
                      fieldbackground=[('active', colors['entry_bg'])],
                      foreground=[('active', colors['fg'])])

        self.update_child_colors(self.root, colors)

        # 更新彩蛋 Label 颜色
        if hasattr(self, 'easter_egg_label'):
            self.easter_egg_label.configure(bg=colors['bg'], fg="gray")

    def update_child_colors(self, widget: tk.Widget, colors: dict) -> None:
        try:
            if isinstance(widget, (tk.LabelFrame, tk.Label, tk.Frame, tk.Toplevel)):
                widget.configure(bg=colors['bg'])
            if isinstance(widget, (tk.LabelFrame, tk.Label)):
                widget.configure(fg=colors['fg'])
            if isinstance(widget, tk.Button):
                widget.configure(bg=colors['button_bg'], fg=colors['fg'])
            if isinstance(widget, tk.Entry):
                widget.configure(bg=colors['entry_bg'], fg=colors['fg'], insertbackground=colors['fg'])
        except:
            pass
        for child in widget.winfo_children():
            self.update_child_colors(child, colors)

    def adjust_window(self) -> None:
        self.root.update_idletasks()
        self.root.geometry(f"{self.root.winfo_reqwidth()}x{self.root.winfo_reqheight()}+0+0")

    # ---------- 界面构建 ----------
    def create_widgets(self) -> None:
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        # 模式
        mode_frame = ttk.LabelFrame(main, text="操作模式", padding=5)
        mode_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=5)
        for mode, label in (('encrypt', '加密'), ('decrypt', '解密')):
            ttk.Radiobutton(mode_frame, text=label, variable=self.mode_var, value=mode).pack(side=tk.LEFT, padx=5)

        # 文件
        file_frame = ttk.LabelFrame(main, text="文件", padding=5)
        file_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)

        for row, label, var, browse_cmd, paste_cmd in (
            (0, "输入文件:", self.input_path, lambda: self.browse_file(True), lambda: self.paste_path(self.input_path)),
            (2, "输出文件:", self.output_path, lambda: self.browse_file(False), lambda: self.paste_path(self.output_path))
        ):
            ttk.Label(file_frame, text=label).grid(row=row, column=0, sticky="w", pady=2)
            ttk.Entry(file_frame, textvariable=var, width=40).grid(row=row, column=1, padx=5, sticky="ew")
            ttk.Button(file_frame, text="浏览...", command=browse_cmd).grid(row=row, column=2, padx=2)
            ttk.Button(file_frame, text="粘贴路径", command=paste_cmd).grid(row=row, column=3, padx=2)

        # 文件信息
        ttk.Label(file_frame, textvariable=self.file_info_var, foreground="gray").grid(row=1, column=0, columnspan=4, sticky="w", pady=2)
        file_frame.columnconfigure(1, weight=1)

        # 参数
        param_frame = ttk.LabelFrame(main, text="参数", padding=5)
        param_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=5)

        # 密钥行 (row0) - 使用 Frame 将显示密钥、随机密钥、复制密钥水平排列，取消右对齐
        ttk.Label(param_frame, text="密钥:").grid(row=0, column=0, sticky="w", pady=2)
        self.key_entry = ttk.Entry(param_frame, textvariable=self.key_var, show="*", width=30)
        self.key_entry.grid(row=0, column=1, padx=5, sticky="w")

        key_controls = ttk.Frame(param_frame)
        key_controls.grid(row=0, column=2, sticky="w", padx=5)

        self.show_key_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(key_controls, text="显示密钥", variable=self.show_key_var,
                        command=lambda: self.key_entry.config(show="" if self.show_key_var.get() else "*")).pack(side=tk.LEFT, padx=2)
        self.random_key_btn = ttk.Button(key_controls, text="随机密钥", command=self.generate_random_key, width=10)
        self.random_key_btn.pack(side=tk.LEFT, padx=2)
        self.copy_key_btn = ttk.Button(key_controls, text="复制密钥", command=self.copy_key_to_clipboard, width=10)
        self.copy_key_btn.pack(side=tk.LEFT, padx=2)

        # 块大小行 (row1)
        ttk.Label(param_frame, text="块大小 (字节):").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Spinbox(param_frame, from_=1, to=10485760, increment=1024,
                    textvariable=self.block_size_var, width=15,
                    command=self.update_file_info).grid(row=1, column=1, padx=5, sticky="w")
        preset_frame = ttk.Frame(param_frame)
        preset_frame.grid(row=1, column=2, padx=5, sticky="e")  # 预设按钮保持右对齐
        for label, size in (("512KB", 524288), ("1MB", 1048576), ("2MB", 2097152), ("4MB", 4194304)):
            ttk.Button(preset_frame, text=label, width=6,
                       command=lambda s=size: (self.block_size_var.set(s), self.update_file_info())).pack(side=tk.LEFT, padx=2)

        # 进度
        progress_frame = ttk.LabelFrame(main, text="进度", padding=5)
        progress_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=5)

        self.progress_bar = ttk.Progressbar(progress_frame, length=400, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=2)
        self.status_text = tk.StringVar(value="就绪")
        ttk.Label(progress_frame, textvariable=self.status_text).pack(anchor="w")
        self.info_text = tk.StringVar(value="")
        ttk.Label(progress_frame, textvariable=self.info_text, foreground="gray").pack(anchor="w")

        # 控制
        control_frame = ttk.Frame(main)
        control_frame.grid(row=4, column=0, columnspan=2, pady=10, sticky="ew")

        left = ttk.Frame(control_frame)
        left.pack(side=tk.LEFT)
        ttk.Checkbutton(left, text="完成后自动打开输出文件夹", variable=self.open_folder_var).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(left, text="暗色模式", variable=self.dark_mode_var,
                        command=lambda: (self.apply_theme('dark' if self.dark_mode_var.get() else 'light'), self.adjust_window())).pack(side=tk.LEFT, padx=5)

        right = ttk.Frame(control_frame)
        right.pack(side=tk.RIGHT)
        ttk.Button(right, text="打开配置文件", command=self.open_config_file).pack(side=tk.LEFT, padx=2)
        self.start_btn = ttk.Button(right, text="开始", command=self.start_operation, width=12)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.close_btn = ttk.Button(right, text="关闭", command=self.on_closing, width=12)
        self.close_btn.pack(side=tk.LEFT, padx=5)

    # ---------- 新增功能：随机密钥 & 复制密钥 ----------
    def generate_random_key(self) -> None:
        """生成16位数字+大小写字母的随机密钥并填入输入框，并自动启用显示密钥"""
        chars = string.ascii_letters + string.digits
        key = ''.join(secrets.choice(chars) for _ in range(16))
        self.key_var.set(key)
        # 自动勾选“显示密钥”并显示明文
        self.show_key_var.set(True)
        self.key_entry.config(show="")

    def copy_key_to_clipboard(self) -> None:
        """将当前密钥复制到剪贴板"""
        key = self.key_var.get()
        if key:
            self.root.clipboard_clear()
            self.root.clipboard_append(key)
            messagebox.showinfo("提示", "密钥已复制到剪贴板")
        else:
            messagebox.showwarning("警告", "密钥为空，无法复制")

    # ---------- 辅助方法 ----------
    def browse_file(self, is_input: bool) -> None:
        title = "选择要加密的文件" if (self.mode_var.get() == "encrypt" and is_input) else "选择要解密的文件"
        path = filedialog.askopenfilename(title=title) if is_input else filedialog.asksaveasfilename(title="选择输出文件位置")
        if path:
            var = self.input_path if is_input else self.output_path
            var.set(path)
            if is_input and not self.output_path.get():
                base = os.path.splitext(path)[0]
                self.output_path.set(base + (".enc" if self.mode_var.get() == "encrypt" else ".dec"))

    def paste_path(self, target_var: tk.StringVar) -> None:
        try:
            text = self.root.clipboard_get().strip()
            if text:
                path = text.splitlines()[0].strip()
                if path:
                    target_var.set(path)
        except:
            pass

    def open_config_file(self) -> None:
        if not os.path.exists(CONFIG_FILE):
            save_config(self.config)
        try:
            open_with_default_app(CONFIG_FILE)
        except Exception as e:
            messagebox.showerror("错误", f"无法打开配置文件: {e}")

    # ---------- 操作控制 ----------
    def start_operation(self) -> None:
        if self.running:
            return
        input_file = self.input_path.get().strip()
        output_file = self.output_path.get().strip()
        key = self.key_var.get().strip()
        if not all((input_file, output_file, key)):
            messagebox.showerror("错误", "请完整填写输入文件、输出文件和密钥")
            return
        if not os.path.exists(input_file):
            messagebox.showerror("错误", f"输入文件不存在: {input_file}")
            return

        block_size = self.block_size_var.get()
        if block_size < 1024:
            messagebox.showwarning("警告", f"块大小为 {block_size} 字节，小于推荐值。\n过小的块会影响性能。\n点击“确定”仍继续。")

        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.close_btn.config(state=tk.DISABLED)
        self.progress_bar['value'] = 0
        self.status_text.set("正在处理...")
        self.info_text.set("")

        self.thread = threading.Thread(target=self.run_operation, args=(input_file, output_file, key, block_size), daemon=True)
        self.thread.start()
        self.poll_thread()

    def run_operation(self, input_file: str, output_file: str, key: str, block_size: int) -> None:
        try:
            if self.mode_var.get() == "encrypt":
                total_time, avg_speed = encrypt_file(input_file, output_file, key, block_size, self.update_progress)
                op_name = "加密"
            else:
                total_time, avg_speed = decrypt_file(input_file, output_file, key, block_size, self.update_progress)
                op_name = "解密"
            self.root.after(0, self.finish_operation, True,
                            f"{op_name}完成 | 总耗时: {format_time(total_time)} | 平均速度: {avg_speed:.1f} MB/s",
                            output_file)
        except Exception as e:
            self.root.after(0, self.finish_operation, False, f"错误: {e}", None)

    def update_progress(self, percent: float, speed_mb: float, elapsed_str: str, eta_str: str) -> None:
        def _update():
            self.progress_bar['value'] = percent
            self.status_text.set(f"进度: {percent:.1f}%")
            self.info_text.set(f"速度: {speed_mb:.1f} MB/s  已用: {elapsed_str}  剩余: {eta_str}")
        self.root.after(0, _update)

    def poll_thread(self) -> None:
        if self.running and self.thread and self.thread.is_alive():
            self.root.after(100, self.poll_thread)
        elif self.running:
            self.finish_operation(False, "操作被意外终止", None)

    def finish_operation(self, success: bool, message: str, output_file: Optional[str] = None) -> None:
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.close_btn.config(state=tk.NORMAL)
        self.progress_bar['value'] = 100 if success else self.progress_bar['value']
        self.status_text.set(message if success else "操作失败")
        if not success:
            self.info_text.set("")
            messagebox.showerror("错误", message)
        else:
            self.info_text.set(message)
            if self.open_folder_var.get() and output_file:
                folder = os.path.dirname(output_file)
                if not folder:
                    folder = "."
                if os.path.exists(folder):
                    try:
                        open_with_default_app(folder)
                    except Exception as e:
                        messagebox.showwarning("警告", f"无法打开文件夹: {e}")
        self.thread = None


# ---------- 启动 ----------
if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()