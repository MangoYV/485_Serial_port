import serial
import serial.tools.list_ports
import tkinter as tk
import os
from tkinter import ttk, messagebox, colorchooser, filedialog, simpledialog
from threading import Thread, Event
import time
import binascii
from datetime import datetime
import configparser
import re

HISTORY_MAX_ITEMS = 100


class AutoReplyHandler:
    def __init__(self, master, debugger):
        self.master = master
        self.debugger = debugger
        self.rules = []
        self.config_file = "com.config"
        self.setup_ui()
        self.load_rules()

    def setup_ui(self):
        self.main_frame = ttk.Frame(self.master)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.main_frame.config(width=425)
        self.master.master.master.master.columnconfigure(1, minsize=425)

        toolbar = ttk.Frame(self.main_frame)
        toolbar.pack(fill=tk.X, pady=2)
        ttk.Button(toolbar, text="添加规则", command=self.add_rule).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="删除选中", command=self.delete_selected).pack(side=tk.LEFT, padx=2)

        self.tree = ttk.Treeview(self.main_frame, columns=('enable', 'match', 'reply', 'hex'),
                                 show='headings', selectmode='extended')

        self.tree.heading('enable', text='启用', anchor=tk.CENTER)
        self.tree.column('enable', width=40, minwidth=40, stretch=False)
        self.tree.heading('match', text='匹配内容')
        self.tree.column('match', width=150, minwidth=100, stretch=True)
        self.tree.heading('reply', text='回复内容')
        self.tree.column('reply', width=150, minwidth=100, stretch=True)
        self.tree.heading('hex', text='HEX格式', anchor=tk.CENTER)
        self.tree.column('hex', width=40, minwidth=40, stretch=False)

        scroll = ttk.Scrollbar(self.main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Motion>", self.on_tree_hover)
        self.tree.bind("<Leave>", self.hide_tooltip)
        self.current_tooltip = None

    def on_tree_hover(self, event):
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell":
            self.hide_tooltip()
            return

        column = self.tree.identify_column(event.x)
        item = self.tree.identify_row(event.y)

        if column in ("#2", "#3"):
            index = int(self.tree.index(item))
            rule = self.rules[index]

            text = rule['match'] if column == "#2" else rule['reply']
            if not text: return

            self.show_tooltip(event.x_root, event.y_root, text)

    def show_tooltip(self, x, y, text):
        if self.current_tooltip:
            self.current_tooltip.destroy()

        self.current_tooltip = tk.Toplevel(self.master)
        self.current_tooltip.wm_overrideredirect(True)
        self.current_tooltip.wm_geometry(f"+{x + 15}+{y + 10}")

        label = ttk.Label(
            self.current_tooltip,
            text=text,
            background="#FFFFE0",
            relief="solid",
            borderwidth=1,
            padding=(3, 1),
            wraplength=300
        )
        label.pack()

    def hide_tooltip(self, event=None):
        if self.current_tooltip:
            self.current_tooltip.destroy()
            self.current_tooltip = None

    def add_rule(self, initial_data=None):
        default_data = {
            'enable': True,
            'match': '',
            'reply': '',
            'hex': False,
            'checksum': 'None'
        }
        if initial_data:
            default_data.update(initial_data)

        if self.edit_rule_dialog(default_data):
            self.rules.append(default_data)
            self._update_treeview()
            self.save_rules()

    def edit_rule_dialog(self, rule_data):
        dlg = tk.Toplevel(self.master)
        dlg.title("编辑应答规则")
        dlg.grab_set()
        dlg.confirmed = False

        dialog_width = 305
        dialog_height = 140
        screen_width = dlg.winfo_screenwidth()
        screen_height = dlg.winfo_screenheight()
        x = (screen_width - dialog_width) // 2
        y = (screen_height - dialog_height) // 2
        dlg.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")

        enable_var = tk.BooleanVar(value=rule_data['enable'])
        match_var = tk.StringVar(value=rule_data['match'])
        reply_var = tk.StringVar(value=rule_data['reply'])
        hex_var = tk.BooleanVar(value=rule_data['hex'])
        checksum_var = tk.StringVar(value=rule_data['checksum'])

        ttk.Checkbutton(dlg, text="启用规则", variable=enable_var).grid(row=0, column=0, columnspan=2, sticky=tk.W)

        ttk.Label(dlg, text="匹配条件:").grid(row=1, column=0, sticky=tk.W)
        match_entry = ttk.Entry(dlg, textvariable=match_var, width=30)
        match_entry.grid(row=1, column=1, padx=2, pady=2)

        ttk.Label(dlg, text="回复内容:").grid(row=2, column=0, sticky=tk.W)
        reply_entry = ttk.Entry(dlg, textvariable=reply_var, width=30)
        reply_entry.grid(row=2, column=1, padx=2, pady=2)

        ttk.Checkbutton(dlg, text="HEX格式 &#9550; ", variable=hex_var).grid(row=3, column=0, sticky=tk.W)

        ttk.Label(dlg, text="校验方式:").grid(row=3, column=1, sticky=tk.W)
        checksum_combo = ttk.Combobox(dlg, values=['None', 'CRC-16', 'XOR'],
                                      textvariable=checksum_var, width=8)
        checksum_combo.grid(row=3, column=1)

        btn_frame = ttk.Frame(dlg)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=5)

        def on_ok():
            dlg.confirmed = True
            dlg.destroy()

        ttk.Button(btn_frame, text="确定", command=on_ok).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="取消", command=dlg.destroy).pack(side=tk.LEFT)

        dlg.wait_window()

        if dlg.confirmed:
            rule_data.update({
                'enable': enable_var.get(),
                'match': match_var.get(),
                'reply': reply_var.get(),
                'hex': hex_var.get(),
                'checksum': checksum_var.get()
            })
            return True
        return False

    def delete_selected(self):
        selected = self.tree.selection()
        for item in reversed(selected):
            index = int(self.tree.index(item))
            del self.rules[index]
        self._update_treeview()
        self.save_rules()

    def on_double_click(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            index = int(self.tree.index(item))
            if self.edit_rule_dialog(self.rules[index]):
                self._update_treeview()
                self.save_rules()

    def _update_treeview(self):
        self.tree.delete(*self.tree.get_children())
        for rule in self.rules:
            status = '&#10003;' if rule['enable'] else '&#10007;'
            self.tree.insert('', 'end', values=(
                status,
                rule['match'],
                rule['reply'],
                'HEX' if rule['hex'] else 'TXT'
            ))

    def check_and_reply(self, received_data):
        if not self.debugger.serial_port or not self.debugger.serial_port.is_open:
            return

        hex_received = ' '.join(f'{b:02X}' for b in received_data)
        str_received = self.debugger.auto_decode(received_data)

        for rule in self.rules:
            if not rule['enable']:
                continue

            if rule['hex']:
                match_str = rule['match'].upper().replace(' ', '')
                received_match = hex_received.replace(' ', '')
            else:
                match_str = rule['match']
                received_match = str_received

            if match_str in received_match:
                self._send_reply(rule)

    def _send_reply(self, rule):
        try:
            if rule['hex']:
                data = binascii.unhexlify(rule['reply'].replace(' ', ''))
            else:
                data = rule['reply'].encode('utf-8')

            data = self._add_checksum(data, rule['checksum'])

            self.debugger.serial_port.write(data)
            self.debugger.tx_counter += len(data)
            self.debugger.update_counters()

            self.debugger.display_data(data, 'send')

        except Exception as e:
            messagebox.showerror("自动应答错误", f"发送失败: {str(e)}")

    def _add_checksum(self, data, checksum_type):
        if checksum_type == 'CRC-16':
            return data + self.debugger.calculate_crc16(data)
        elif checksum_type == 'XOR':
            return data + bytes([self.debugger.calculate_xor(data)])
        return data

    def save_rules(self):
        config = configparser.ConfigParser()
        config.read(self.config_file, encoding='utf-8')

        for section in config.sections():
            if section.startswith("AutoReply"):
                config.remove_section(section)

        config['AutoReply'] = {'count': str(len(self.rules))}
        for idx, rule in enumerate(self.rules):
            section = f"AutoReply{idx}"
            config[section] = {
                'enable': str(rule['enable']),
                'match': rule['match'],
                'reply': rule['reply'],
                'hex': str(rule['hex']),
                'checksum': rule['checksum']
            }

        with open(self.config_file, 'w', encoding='utf-8') as f:
            config.write(f)

    def load_rules(self):
        config = configparser.ConfigParser()
        config.read(self.config_file, encoding='utf-8')

        if 'AutoReply' in config:
            rule_count = config.getint('AutoReply', 'count', fallback=0)
            for i in range(rule_count):
                section = f"AutoReply{i}"
                if config.has_section(section):
                    self.rules.append({
                        'enable': config.getboolean(section, 'enable'),
                        'match': config.get(section, 'match'),
                        'reply': config.get(section, 'reply'),
                        'hex': config.getboolean(section, 'hex'),
                        'checksum': config.get(section, 'checksum')
                    })
            self._update_treeview()


class HistoryHandler:
    def __init__(self, master, debugger):
        self.master = master
        self.debugger = debugger
        self.history = []
        self.config_file = "com.config"
        print(f"[UI DEBUG] 历史记录容器类型: {type(master)}")
        self.setup_ui()
        self.load_history()

    def setup_ui(self):
        self.frame = ttk.Frame(self.master)
        self.frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.frame.columnconfigure(0, weight=1)
        self.frame.rowconfigure(0, weight=1)

        self.listbox = tk.Listbox(
            self.frame,
            selectmode=tk.EXTENDED,
            font=('微软雅黑', 10),
            relief=tk.GROOVE,
            borderwidth=1
        )
        scrollbar = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=scrollbar.set)

        self.listbox.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        btn_frame = ttk.Frame(self.frame)
        btn_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(5, 0))

        ttk.Button(btn_frame, text="删除选中", command=self.delete_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="清空历史", command=self.clear_history).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="发送选中", command=self.send_selected).pack(side=tk.LEFT, padx=2)
        self.context_menu = tk.Menu(self.master, tearoff=0)
        self.context_menu.add_command(label="发送", command=self.send_selected)
        self.context_menu.add_command(label="删除", command=self.delete_selected)
        self.listbox.bind("<Double-1>", lambda e: self.send_selected())
        self.listbox.bind("<Button-3>", self.show_context_menu)
        self.frame.update_idletasks()
        print("[UI DEBUG] 历史记录UI初始化完成")

    def show_context_menu(self, event):
        try:
            index = self.listbox.nearest(event.y)
            if index == -1:
                return

            bbox = self.listbox.bbox(index)
            if not bbox:
                return

            _, y_start, _, height = bbox

            if not (y_start <= event.y <= y_start + height):
                print(f"[DEBUG] 点击在行间隙（Y范围：{y_start}-{y_start + height}，实际Y：{event.y}）")
                return

            self.listbox.selection_clear(0, tk.END)
            self.listbox.selection_set(index)

            self.context_menu.tk_popup(event.x_root, event.y_root)

        except Exception as e:
            print(f"[ERROR] 右键处理失败: {str(e)}")

    def add_history(self, command, is_hex):
        self.history = [item for item in self.history if item['command'] != command]

        self.history.insert(0, {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'command': command,
            'hex': is_hex
        })

        if len(self.history) > HISTORY_MAX_ITEMS:
            self.history = self.history[:HISTORY_MAX_ITEMS]

        self.save_history()
        self.update_listbox()

    def delete_selected(self):
        selected = self.listbox.curselection()
        if not selected:
            return
        for index in reversed(selected):
            del self.history[index]
        self.save_history()
        self.update_listbox()

    def clear_history(self):
        if messagebox.askyesno("确认清空", "确定要清空所有历史记录吗？"):
            self.history = []
            self.save_history()
            self.update_listbox()

    def send_selected(self):
        selected = self.listbox.curselection()
        for index in selected:
            item = self.history[index]
            self.debugger.send_custom_command(item['command'], item['hex'])

    def update_listbox(self):
        self.listbox.delete(0, tk.END)
        for item in self.history:
            prefix = "[HEX]" if item['hex'] else "[TXT]"
            self.listbox.insert(tk.END, f"{prefix} {item['timestamp']} - {item['command'][:50]}")

    def load_history(self):
        config = configparser.ConfigParser()
        config.read(self.config_file, encoding='utf-8')

        if 'History' in config:
            history_count = config.getint('History', 'count', fallback=0)
            self.history = []
            for i in range(history_count):
                section = f"History{i}"
                if config.has_section(section):
                    self.history.append({
                        'timestamp': config.get(section, 'timestamp'),
                        'command': config.get(section, 'command'),
                        'hex': config.getboolean(section, 'hex')
                    })
            self.update_listbox()

    def save_history(self):
        config = configparser.ConfigParser()
        config.read(self.config_file, encoding='utf-8')

        for section in config.sections():
            if section.startswith("History"):
                config.remove_section(section)

        config['History'] = {'count': str(len(self.history))}
        for i, item in enumerate(self.history):
            section = f"History{i}"
            config[section] = {
                'timestamp': item['timestamp'],
                'command': item['command'],
                'hex': str(item['hex'])
            }

        with open(self.config_file, 'w', encoding='utf-8') as f:
            config.write(f)


class PresetCommand:
    def __init__(self, master, debugger):
        self.master = master
        self.debugger = debugger
        self.commands = []
        self.config_file = "com.config"
        self.max_commands = 100
        self.config = configparser.ConfigParser(allow_no_value=True)
        self.config.optionxform = lambda option: option
        self.setup_ui()
        self._bind_scroll_events()
        self.tooltips = {
            0: "HEX发送：勾选后以十六进制格式发送指令",
            1: "指令内容（双击修改注释）：\n- 输入要发送的指令内容\n- 支持ASCII或HEX格式",
            2: "点击发送：点击立即发送对应指令",
            3: "发送顺序：\n- 0：不参与循环发送\n- 数字越大发送越晚\n- 相同顺序同时发送",
            4: "发送延时：本条指令发送完成后\n等待指定毫秒再发送下一条",
            5: "删除指令：点击删除本行配置"
        }
        if not os.path.exists(self.config_file):
            self.create_default_commands()
        else:
            self.load_commands()

    def setup_ui(self):
        self.main_frame = ttk.Frame(self.master)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        top_row = ttk.Frame(self.main_frame)
        top_row.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(top_row, text="<--拖动加宽", foreground="gray").pack(side=tk.LEFT, padx=5)
        self.loop_send_var = tk.BooleanVar()
        ttk.Checkbutton(top_row, text="循环发送", variable=self.loop_send_var,
                        command=lambda: self.debugger.toggle_loop_send()).pack(side=tk.LEFT)

        table_container = ttk.Frame(self.main_frame)
        table_container.pack(fill=tk.BOTH, expand=True)

        header_frame = ttk.Frame(table_container)
        header_frame.pack(fill=tk.X)
        header_columns = [
            ("HEX", 6), ("字符串(双击改名)", 1), ("点击发送", 10),
            ("顺序", 6), ("延时（ms）", 8), ("删", 4)
        ]
        for col, (text, width) in enumerate(header_columns):
            lbl = ttk.Label(header_frame, text=text, width=width, anchor=tk.CENTER)
            lbl.grid(row=0, column=col, sticky='ew', padx=2)
        header_frame.grid_columnconfigure(1, weight=1)

        scroll_container = ttk.Frame(table_container)
        scroll_container.pack(fill=tk.BOTH, expand=True)

        self.canvas = tk.Canvas(scroll_container, borderwidth=0, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(scroll_container, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)

        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw", tags="scroll_frame")

        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(
            scrollregion=self.canvas.bbox("all")
        ))
        self.canvas.bind("<Configure>", self._on_canvas_resize)

        self.add_btn = ttk.Button(self.main_frame, text="添加预置命令", command=self.add_preset_command)
        self.add_btn.pack(side=tk.BOTTOM, anchor=tk.E, padx=5, pady=2)

    def _bind_scroll_events(self):
        for widget in [self.canvas, self.scrollable_frame]:
            widget.bind("<MouseWheel>", self._on_mouse_wheel)
            widget.bind("<Button-4>", self._on_mouse_wheel)
            widget.bind("<Button-5>", self._on_mouse_wheel)

        for cmd in self.commands:
            self._bind_row_events(cmd['row_frame'])

    def _bind_row_events(self, row_frame):
        row_frame.bind("<MouseWheel>", self._on_mouse_wheel)
        row_frame.bind("<Button-4>", self._on_mouse_wheel)
        row_frame.bind("<Button-5>", self._on_mouse_wheel)

    def _on_mouse_wheel(self, event):
        if event.delta:
            delta = event.delta
        elif event.num in (4, 5):
            delta = 1 if event.num == 4 else -1
        else:
            return

        scroll_units = -1 * (delta // abs(delta))

        self.canvas.yview_scroll(scroll_units, "units")
        return "break"

    def _update_button_numbers(self):
        for idx, cmd in enumerate(self.commands):
            current_text = cmd['widgets']['comment_btn']['text'].split(' ', 1)[-1]
            cmd['widgets']['comment_btn'].config(text=f"#{idx + 1} {current_text}")

    def _on_canvas_resize(self, event):
        canvas_width = event.width
        self.canvas.itemconfigure("scroll_frame", width=canvas_width)

    def add_preset_command(self, initial_data=None):
        if len(self.commands) >= self.max_commands:
            messagebox.showwarning("提示", f"最多只能添加{self.max_commands}条指令")
            return

        row_frame = ttk.Frame(self.scrollable_frame)
        row_frame.pack(fill=tk.X, pady=1)

        widgets = {
            'hex_var': tk.BooleanVar(),
            'command_entry': ttk.Entry(row_frame),
            'comment_btn': ttk.Button(row_frame, text=f"#{len(self.commands) + 1} 无注释", width=12),
            'order_entry': ttk.Entry(row_frame, width=4),
            'delay_entry': ttk.Entry(row_frame, width=6),
            'del_btn': ttk.Button(row_frame, text="-", width=2)
        }
        for widget in widgets.values():
            if isinstance(widget, (ttk.Entry, ttk.Button)):
                widget.bind("<MouseWheel>", self._on_mouse_wheel)
                widget.bind("<Button-4>", self._on_mouse_wheel)
                widget.bind("<Button-5>", self._on_mouse_wheel)
        validate_num = (self.master.register(self.validate_number), '%P')
        widgets['order_entry'].insert(0, "0")
        widgets['order_entry'].config(validate="key", validatecommand=validate_num)
        widgets['delay_entry'].insert(0, "1000")
        widgets['delay_entry'].config(validate="key", validatecommand=validate_num)

        ttk.Checkbutton(row_frame, variable=widgets['hex_var']).grid(row=0, column=0, padx=2, sticky='w')
        widgets['command_entry'].grid(row=0, column=1, padx=2, sticky='ew')
        widgets['comment_btn'].grid(row=0, column=2, padx=2, sticky='e')
        widgets['order_entry'].grid(row=0, column=3, padx=2, sticky='e')
        widgets['delay_entry'].grid(row=0, column=4, padx=2, sticky='e')
        widgets['del_btn'].grid(row=0, column=5, padx=2, sticky='e')

        widgets['command_entry'].bind("<Double-1>", lambda e, w=widgets: self.rename_comment(w))
        widgets['comment_btn'].config(command=lambda w=widgets: self.debugger.send_custom_command(
            w['command_entry'].get(), w['hex_var'].get()))
        widgets['del_btn'].config(command=lambda w=row_frame: self.delete_command(w))
        self._bind_row_events(row_frame)
        if initial_data:
            widgets['hex_var'].set(initial_data.get('hex', False))
            widgets['command_entry'].insert(0, initial_data.get('command', ''))
            widgets['comment_btn'].config(text=f"#{len(self.commands) + 1} {initial_data.get('comment', '无注释')}")
            widgets['order_entry'].delete(0, tk.END)
            widgets['order_entry'].insert(0, str(initial_data.get('order', 0)))
        for entry in [widgets['command_entry'], widgets['order_entry'], widgets['delay_entry']]:
            entry.bind("<Button-3>", self.debugger.show_context_menu)

        for col, widget in enumerate(widgets.values()):
            if col != 0:
                self._add_tooltip(widget, col)

        row_frame.columnconfigure(1, weight=1)

        self.commands.append({"row_frame": row_frame, "widgets": widgets})
        self._save_commands()

        widgets['hex_var'].trace_add('write', lambda *_: self._save_commands())
        widgets['command_entry'].bind('<KeyRelease>', lambda e: self._save_commands())
        widgets['order_entry'].bind('<KeyRelease>', lambda e: self._save_commands())
        widgets['delay_entry'].bind('<KeyRelease>', lambda e: self._save_commands())

        self._update_button_numbers()

    def _add_tooltip(self, widget, col_index):
        tooltip_text = self.tooltips.get(col_index, "")
        tooltip = tk.Toplevel(self.master)
        tooltip.withdraw()
        tooltip.overrideredirect(True)

        label = ttk.Label(tooltip, text=tooltip_text, background="#FFFFE0",
                          relief="solid", borderwidth=1, padding=(4, 2),
                          font=('微软雅黑', 9))
        label.pack()

        tooltip_visible = False
        scheduled_id = None

        def show_tooltip():
            nonlocal tooltip_visible
            tooltip_visible = True
            x = widget.winfo_rootx() + 20
            y = widget.winfo_rooty() + 25
            tooltip.geometry(f"+{x}+{y}")
            tooltip.deiconify()

        def schedule_show():
            nonlocal scheduled_id
            scheduled_id = self.master.after(500, show_tooltip)

        def hide_tooltip():
            nonlocal tooltip_visible, scheduled_id
            if scheduled_id:
                self.master.after_cancel(scheduled_id)
            if tooltip_visible:
                tooltip.withdraw()
            tooltip_visible = False

        widget.bind("<Enter>", lambda e: schedule_show())
        widget.bind("<Leave>", lambda e: hide_tooltip())
        widget.bind("<ButtonPress>", lambda e: hide_tooltip())

    def validate_number(self, value):
        return value.isdigit() or value == ""

    def rename_comment(self, widgets):
        current_text = widgets['comment_btn'].cget('text')
        new_name = simpledialog.askstring(
            "修改注释",
            "请输入新的按钮名称:",
            parent=self.master,
            initialvalue=current_text
        )
        if new_name:
            widgets['comment_btn'].config(text=new_name)
            self._save_commands()
            self._update_button_numbers()

    def send_command(self, widgets):
        command = widgets['command_entry'].get()
        if not command:
            return

        hex_send = widgets['hex_var'].get()
        self.debugger.send_custom_command(command, hex_send)

    def delete_command(self, row_frame):
        if messagebox.askyesno("确认删除", "确定要删除该指令吗？"):
            for cmd in self.commands:
                if cmd['row_frame'] == row_frame:
                    self.commands.remove(cmd)
                    break
            row_frame.destroy()
            self._save_commands()
            self._update_button_numbers()

    def get_sorted_commands(self):
        valid_commands = []
        for cmd in self.commands:
            order = cmd['widgets']['order_entry'].get()
            if order.isdigit() and int(order) > 0:
                valid_commands.append({
                    'order': int(order),
                    'delay': int(cmd['widgets']['delay_entry'].get()),
                    'command': cmd['widgets']['command_entry'].get(),
                    'hex': cmd['widgets']['hex_var'].get()
                })
        return sorted(valid_commands, key=lambda x: x['order'])

    def create_default_commands(self):
        self.config = configparser.ConfigParser()
        self.config.optionxform = lambda option: option

        self.config['Meta'] = {
            'version': '2.0',
            'create_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'comment': 'Auto generated default config'
        }
        default_commands = [
            {'hex': True, 'command': '01 03 00 00 00 01', 'comment': '读保持寄存器', 'order': 1, 'delay': 1000},
            {'hex': True, 'command': '01 06 00 00 00 01 00 01', 'comment': '写单个寄存器', 'order': 2, 'delay': 3000},
            {'hex': True, 'command': '01 03 00 01 00 01', 'comment': '读输入寄存器', 'order': 3, 'delay': 1000},
            {'hex': True, 'command': '01 04 00 00 00 01', 'comment': '读输入状态', 'order': 4, 'delay': 3000},
            *[
                {'hex': True, 'command': cmd, 'comment': comment, 'order': 0, 'delay': 1000}
                for cmd, comment in [
                    ('01 01 00 00 00 01', '读线圈状态'),
                    ('01 05 00 00 FF 00', '写单个线圈'),
                    ('01 0F 00 00 00 01', '写多个线圈'),
                    ('01 10 00 00 00 02 04 00 01', '写多个寄存器'),
                    ('01 03 00 00 00 01', '读设备标识'),
                    ('08 01 00 00 00 01', '回送测试'),
                ]
            ]
        ]
        for idx, cmd in enumerate(default_commands):
            section_name = f"Command{idx}"
            self.config[section_name] = {
                'hex': str(cmd['hex']),
                'command': cmd['command'],
                'comment': cmd['comment'],
                'order': str(cmd['order']),
                'delay': str(cmd['delay'])
            }

            self.add_preset_command(initial_data=cmd)

        with open(self.config_file, 'w', encoding='utf-8') as f:
            self.config.write(f)

    def load_commands(self):
        try:
            self.config.read(self.config_file, encoding='utf-8')

            command_sections = sorted(
                [s for s in self.config.sections() if s.startswith("Command")],
                key=lambda x: int(x[7:])
            )

            for section in command_sections:
                cmd_data = {
                    'hex': self.config.getboolean(section, 'hex'),
                    'command': self.config[section]['command'],
                    'comment': self.config[section].get('comment', '无注释'),
                    'order': self.config[section].get('order', '0'),
                    'delay': self.config[section].get('delay', '1000')
                }
                self.add_preset_command(initial_data=cmd_data)

        except Exception as e:
            messagebox.showerror("配置加载错误",
                                 f"配置文件格式错误: {str(e)}\n将使用默认配置")
            if os.path.exists(self.config_file):
                os.rename(self.config_file, f"{self.config_file}.bak")
            self.create_default_commands()

    def _save_commands(self):
        new_config = configparser.ConfigParser()
        new_config.optionxform = lambda option: option

        for section in self.config.sections():
            if not section.startswith("Command"):
                new_config[section] = self.config[section]

        for idx, cmd in enumerate(self.commands):
            section_name = f"Command{idx}"
            widgets = cmd['widgets']

            new_config[section_name] = {
                'hex': str(widgets['hex_var'].get()),
                'command': widgets['command_entry'].get(),
                'comment': widgets['comment_btn']['text'].split(' ', 1)[-1],
                'order': widgets['order_entry'].get(),
                'delay': widgets['delay_entry'].get()
            }

        with open(self.config_file, 'w', encoding='utf-8') as f:
            new_config.write(f)


class SerialDebugger:
    def __init__(self, master):
        self.master = master
        self.serial_port = None
        self.receive_flag = Event()
        self.auto_send_flag = False
        self.rx_counter = 0
        self.tx_counter = 0
        self.recv_color = '#000000'
        self.send_color = '#0000FF'
        self.extension_visible = False
        self.drag_start_x = 0
        self.initial_width = 425
        self.is_dragging = False

        self.receive_buffer = bytearray()
        self.last_receive_time = 0
        self.frame_timeout = 0.05
        self.min_frame_length = 4
        self.max_frame_length = 256

        temp = tk.Checkbutton(master)
        self.default_bg = temp.cget('bg')
        temp.destroy()

        self.style = ttk.Style()
        self.style.configure('Yellow.TCombobox', fieldbackground='yellow')

        self.setup_ui()
        self.setup_extension_window()
        self.preset_commands = PresetCommand(self.preset_frame, self)
        self.auto_reply_handler = AutoReplyHandler(self.auto_reply_frame, self)
        self.extension_frame.grid_remove()
        self.master.grid_columnconfigure(1, weight=0, minsize=0)

        self.update_ports()

        self.config_file = "com.config"
        self.load_serial_settings()
        self.port_combo.bind("<<ComboboxSelected>>", self.on_port_change)

        self.loop_send_active = False
        self.context_menu = None
        self.create_context_menu()

    def setup_ui(self):
        self._center_window(900, 600)
        self.master.title("485串口调试工具")
        self.master.minsize(650, 450)

        self.master.grid_columnconfigure(0, weight=1)
        self.master.grid_columnconfigure(1, weight=0, minsize=0)
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_rowconfigure(1, weight=0)
        self.master.grid_rowconfigure(2, weight=0)

        display_frame = ttk.Frame(self.master)
        display_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        self.text_display = tk.Text(display_frame, state=tk.DISABLED, wrap=tk.WORD)
        self.text_display.bind("<Button-3>", self.show_context_menu)
        scroll_display = ttk.Scrollbar(display_frame, orient="vertical", command=self.text_display.yview)
        self.text_display.configure(yscrollcommand=scroll_display.set)

        self.text_display.grid(row=0, column=0, sticky="nsew")
        scroll_display.grid(row=0, column=1, sticky="ns")
        display_frame.grid_columnconfigure(0, weight=1)
        display_frame.grid_rowconfigure(0, weight=1)

        control_frame = ttk.Frame(self.master)
        control_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=5, pady=2)
        control_frame.grid_columnconfigure(0, minsize=200, weight=0)
        control_frame.grid_columnconfigure(1, weight=1)
        control_frame.grid_columnconfigure(2, minsize=250, weight=0)
        control_frame.grid_rowconfigure(0, minsize=155, weight=0)

        self.setup_serial_controls(control_frame)
        self.setup_send_controls(control_frame)
        self.setup_function_controls(control_frame)

        self.setup_status_bar()

    def _center_window(self, width, height):
        screen_width = self.master.winfo_screenwidth()
        screen_height = self.master.winfo_screenheight()

        x = (screen_width - width) // 2
        y = (screen_height - height) // 2

        self.master.geometry(f"{width}x{height}+{x}+{y}")

    def setup_extension_window(self):
        self.extension_frame = ttk.Frame(self.master)
        self.extension_frame.grid(row=0, column=1, sticky="nsew")

        self.grip = ttk.Frame(self.extension_frame, width=5, cursor="sb_h_double_arrow")
        self.grip.pack(side="left", fill="y")

        self.grip.bind("<Enter>", self.on_grip_enter)
        self.grip.bind("<Leave>", self.on_grip_leave)
        self.grip.bind("<ButtonPress-1>", self.on_grip_press)
        self.grip.bind("<B1-Motion>", self.on_grip_drag)
        self.grip.bind("<ButtonRelease-1>", self.on_grip_release)

        self.notebook = ttk.Notebook(self.extension_frame)
        self.notebook.pack(side="left", expand=True, fill='both')

        self.preset_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.preset_frame, text="预置指令")

        self.auto_reply_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.auto_reply_frame, text="自动答复")

        self.history_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.history_frame, text="历史记录")
        self.history_handler = HistoryHandler(self.history_frame, self)
        self.conversion_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.conversion_frame, text="转换工具")
        self.setup_conversion_tools()

    def setup_conversion_tools(self):
        main_frame = ttk.Frame(self.conversion_frame)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        hex_dec_frame = ttk.LabelFrame(main_frame, text="十六进制 &#8652; 十进制", padding=10)
        hex_dec_frame.pack(fill="x", pady=5)

        ttk.Label(hex_dec_frame, text="十六进制:").grid(row=0, column=0, sticky="w")
        self.hex_input = ttk.Entry(hex_dec_frame, width=30)
        self.hex_input.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(hex_dec_frame, text="十进制:").grid(row=1, column=0, sticky="w")
        self.dec_input = ttk.Entry(hex_dec_frame, width=30)
        self.dec_input.grid(row=1, column=1, padx=5, pady=5)

        ttk.Button(hex_dec_frame, text="十六进制 &#9658;&#9658; 十进制", command=self.hex_to_dec).grid(row=0, column=2,
                                                                                                       padx=5)
        ttk.Button(hex_dec_frame, text="十进制 &#9658;&#9658; 十六进制", command=self.dec_to_hex).grid(row=1, column=2,
                                                                                                       padx=5)

        hex_ascii_frame = ttk.LabelFrame(main_frame, text="Hex &#8652; ASCII", padding=10)
        hex_ascii_frame.pack(fill="x", pady=5)

        ttk.Label(hex_ascii_frame, text="Hex:").grid(row=0, column=0, sticky="w")
        self.hex_ascii_input = ttk.Entry(hex_ascii_frame, width=30)
        self.hex_ascii_input.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(hex_ascii_frame, text="ASCII:").grid(row=1, column=0, sticky="w")
        self.ascii_input = ttk.Entry(hex_ascii_frame, width=30)
        self.ascii_input.grid(row=1, column=1, padx=5, pady=5)

        ttk.Button(hex_ascii_frame, text="Hex &#9658;&#9658; ASCII", command=self.hex_to_ascii).grid(row=0, column=2,
                                                                                                     padx=5)
        ttk.Button(hex_ascii_frame, text="ASCII &#9658;&#9658; Hex", command=self.ascii_to_hex).grid(row=1, column=2,
                                                                                                     padx=5)

    def hex_to_dec(self):
        hex_str = self.hex_input.get().strip()
        try:
            if hex_str:
                dec_value = int(hex_str, 16)
                self.dec_input.delete(0, tk.END)
                self.dec_input.insert(0, str(dec_value))
            else:
                messagebox.showwarning("输入错误", "请输入十六进制值")
        except ValueError:
            messagebox.showerror("转换错误", "无效的十六进制格式")

    def dec_to_hex(self):
        dec_str = self.dec_input.get().strip()
        try:
            if dec_str:
                hex_value = hex(int(dec_str))[2:].upper()
                self.hex_input.delete(0, tk.END)
                self.hex_input.insert(0, hex_value)
            else:
                messagebox.showwarning("输入错误", "请输入十进制值")
        except ValueError:
            messagebox.showerror("转换错误", "无效的十进制格式")

    def hex_to_ascii(self):
        hex_str = self.hex_ascii_input.get().strip()
        try:
            if hex_str:
                ascii_value = bytes.fromhex(hex_str).decode('ascii')
                self.ascii_input.delete(0, tk.END)
                self.ascii_input.insert(0, ascii_value)
            else:
                messagebox.showwarning("输入错误", "请输入Hex值")
        except ValueError:
            messagebox.showerror("转换错误", "无效的Hex格式")

    def ascii_to_hex(self):
        ascii_str = self.ascii_input.get().strip()
        try:
            if ascii_str:
                hex_value = ascii_str.encode('ascii').hex().upper()
                self.hex_ascii_input.delete(0, tk.END)
                self.hex_ascii_input.insert(0, hex_value)
            else:
                messagebox.showwarning("输入错误", "请输入ASCII值")
        except UnicodeEncodeError:
            messagebox.showerror("转换错误", "无效的ASCII格式")

    def validate_hex_input(self, hex_str):
        try:
            int(hex_str, 16)
            return True
        except ValueError:
            return False

    def validate_dec_input(self, dec_str):
        try:
            int(dec_str)
            return True
        except ValueError:
            return False

    def on_grip_enter(self, event):
        self.grip.config(cursor="sb_h_double_arrow")

    def on_grip_leave(self, event):
        if not self.is_dragging:
            self.grip.config(cursor="")

    def on_grip_press(self, event):
        self.is_dragging = True
        self.drag_start_x = event.x_root
        self.initial_width = self.extension_frame.winfo_width()

    def on_grip_drag(self, event):
        if self.is_dragging:
            delta = self.drag_start_x - event.x_root
            new_width = max(425, self.initial_width + delta)
            self.master.grid_columnconfigure(1, minsize=new_width, weight=0)
            self.master.update_idletasks()

    def on_grip_release(self, event):
        self.is_dragging = False
        self.initial_width = self.extension_frame.winfo_width()
        self.grip.config(cursor="sb_h_double_arrow")

    def toggle_extension(self):
        self.extension_visible = not self.extension_visible

        if self.extension_visible:
            self.extension_frame.grid(row=0, column=1, sticky="nsew")
            self.master.grid_columnconfigure(1, minsize=425, weight=0)
            self.extension_btn.config(text="更多 <<")
        else:
            self.extension_frame.grid_remove()
            self.master.grid_columnconfigure(1, weight=0, minsize=0)
            self.extension_btn.config(text="更多 >>")
        self.master.update_idletasks()

    def setup_status_bar(self):
        status_bar = ttk.Frame(self.master, height=22)
        status_bar.grid(row=2, column=0, columnspan=2, sticky="sew")

        self.status_conn = ttk.Label(status_bar, text="未连接", anchor=tk.W)
        self.status_rx = ttk.Label(status_bar, text="RX:0", width=8)
        self.status_tx = ttk.Label(status_bar, text="TX:0", width=8)
        self.status_author = ttk.Label(status_bar, text="bye", anchor=tk.E)

        self.status_conn.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.status_rx.pack(side=tk.LEFT, padx=5)
        self.status_tx.pack(side=tk.LEFT, padx=5)
        self.status_author.pack(side=tk.RIGHT)

    def setup_serial_controls(self, parent):
        frame = ttk.LabelFrame(parent, text="串口设置", padding=5)
        frame.grid(row=0, column=0, sticky="nsew", padx=2)
        frame.grid_propagate(False)
        frame.config(width=200, height=155)

        frame.grid_columnconfigure(1, weight=1)
        row = 0

        ttk.Label(frame, text="端口号:").grid(row=row, column=0, sticky=tk.W)
        self.port_combo = ttk.Combobox(frame)
        self.port_combo.grid(row=row, column=1, sticky=tk.EW, padx=6)
        row += 1

        ttk.Label(frame, text="波特率:").grid(row=row, column=0, sticky=tk.W)
        self.baud_combo = ttk.Combobox(frame, values=[
            '300', '600', '1200', '2400', '4800', '9600',
            '14400', '19200', '38400', '57600', '115200'
        ])
        self.baud_combo.set('9600')
        self.baud_combo.grid(row=row, column=1, sticky=tk.EW, padx=6)
        row += 1

        param_row = ttk.Frame(frame)
        param_row.grid(row=row, column=0, columnspan=2, sticky=tk.EW)
        ttk.Label(param_row, text="数据位:").grid(row=0, column=0, padx=1)
        self.data_bits = ttk.Combobox(param_row, values=['5', '6', '7', '8'], width=3)
        self.data_bits.set('8')
        self.data_bits.grid(row=0, column=1, padx=4)
        ttk.Label(param_row, text="校验:").grid(row=0, column=2, padx=1)
        self.parity = ttk.Combobox(param_row, values=['无', '奇校验', '偶校验'], width=3)
        self.parity.set('无')
        self.parity.grid(row=0, column=3, sticky=tk.EW)
        param_row.grid_columnconfigure(3, weight=1)
        row += 1

        param_row = ttk.Frame(frame)
        param_row.grid(row=row, column=0, columnspan=2, sticky=tk.EW)
        ttk.Label(param_row, text="停止位:").grid(row=0, column=0, padx=1)
        self.stop_bits = ttk.Combobox(param_row, values=['1', '1.5', '2'], width=3)
        self.stop_bits.set('1')
        self.stop_bits.grid(row=0, column=1, padx=4)
        ttk.Label(param_row, text="流控:").grid(row=0, column=2, padx=1)
        self.flow_control = ttk.Combobox(param_row, values=['无', 'RTS/CTS', 'XON/XOFF'], width=3)
        self.flow_control.set('无')
        self.flow_control.grid(row=0, column=3, sticky=tk.EW)
        param_row.grid_columnconfigure(3, weight=1)
        row += 1

        self.open_btn = ttk.Button(frame, text="打开端口", command=self.toggle_serial)
        self.open_btn.grid(row=row, column=0, columnspan=2, pady=5, sticky=tk.EW)

    def setup_send_controls(self, parent):
        frame = ttk.LabelFrame(parent, text="发送区", padding=5)
        frame.grid(row=0, column=1, sticky="nsew", padx=2)
        frame.grid_propagate(False)
        frame.config(height=155)

        frame.grid_rowconfigure(0, weight=0)
        frame.grid_rowconfigure(1, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        top_row = ttk.Frame(frame)
        top_row.grid(row=0, column=0, sticky="ew", pady=2)
        ttk.Button(top_row, text="文件发送", command=self.send_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_row, text="数据存至文件", command=self.save_data).pack(side=tk.LEFT, padx=2)
        self.checksum_label = tk.Label(top_row, text="末尾添加校验:")
        self.checksum_label.pack(side=tk.LEFT)

        self.checksum_combo = ttk.Combobox(top_row, values=['None', 'CRC-16', 'XOR'], width=8)
        self.checksum_combo.set('None')
        self.checksum_combo.pack(side=tk.LEFT, padx=2)
        self.checksum_combo.bind("<<ComboboxSelected>>", self.on_checksum_selected)
        self.on_checksum_selected(None)

        text_frame = ttk.Frame(frame)
        text_frame.grid(row=1, column=0, sticky="nsew")

        self.send_text = tk.Text(text_frame, wrap=tk.WORD, font=('Consolas', 10))
        self.send_text.bind("<Button-3>", self.show_context_menu)
        scroll_send = ttk.Scrollbar(text_frame, orient="vertical", command=self.send_text.yview)
        self.send_text.configure(yscrollcommand=scroll_send.set)

        self.send_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_send.pack(side=tk.RIGHT, fill=tk.Y)

    def on_checksum_selected(self, event):
        selected = self.checksum_combo.get()
        if selected != 'None':
            self.checksum_combo.config(style='Yellow.TCombobox')
            self.checksum_label.config(bg='yellow')
        else:
            self.checksum_combo.config(style='TCombobox')
            self.checksum_label.config(bg=self.default_bg)

    def setup_function_controls(self, parent):
        frame = ttk.LabelFrame(parent, text="功能设置", padding=5)
        frame.grid(row=0, column=2, sticky="nsew", padx=2)
        frame.grid_propagate(False)
        frame.config(width=250, height=155)

        frame.grid_columnconfigure(0, weight=1)

        top_row = ttk.Frame(frame)
        top_row.grid(row=0, column=0, sticky="ew", pady=2)
        self.hex_send = tk.BooleanVar()
        self.hex_send_cb = tk.Checkbutton(top_row, text="Hex发送", variable=self.hex_send)
        self.hex_send_cb.pack(side=tk.LEFT)
        self.hex_send.trace_add('write',
                                lambda *args: self.update_checkbutton_bg(self.hex_send_cb, self.hex_send))
        self.hex_display = tk.BooleanVar()
        self.hex_display_cb = tk.Checkbutton(top_row, text="Hex显示", variable=self.hex_display)
        self.hex_display_cb.pack(side=tk.LEFT, padx=5)
        self.hex_display.trace_add('write', lambda *args: self.update_checkbutton_bg(self.hex_display_cb,
                                                                                     self.hex_display))
        ttk.Button(top_row, text="清空窗口", command=self.clear_display).pack(side=tk.RIGHT)

        middle_row = ttk.Frame(frame)
        middle_row.grid(row=1, column=0, sticky="ew", pady=2)
        self.timestamp = tk.BooleanVar()
        self.timestamp_cb = tk.Checkbutton(middle_row, text="时间戳", variable=self.timestamp)
        self.timestamp_cb.pack(side=tk.LEFT)
        self.timestamp.trace_add('write',
                                 lambda *args: self.update_checkbutton_bg(self.timestamp_cb, self.timestamp))
        color_frame = ttk.Frame(middle_row)
        color_frame.pack(side=tk.RIGHT)
        ttk.Label(color_frame, text="收:").pack(side=tk.LEFT)
        self.recv_color_lbl = tk.Label(color_frame, width=2, bg=self.recv_color, relief="solid")
        self.recv_color_lbl.bind("<Button-1>", lambda e: self.choose_color('recv'))
        self.recv_color_lbl.pack(side=tk.LEFT, padx=2)
        ttk.Label(color_frame, text="发:").pack(side=tk.LEFT)
        self.send_color_lbl = tk.Label(color_frame, width=2, bg=self.send_color, relief="solid")
        self.send_color_lbl.bind("<Button-1>", lambda e: self.choose_color('send'))
        self.send_color_lbl.pack(side=tk.LEFT, padx=2)

        auto_frame = ttk.Frame(frame)
        auto_frame.grid(row=2, column=0, sticky="ew", pady=2)
        ttk.Label(auto_frame, text="间隔(ms):").pack(side=tk.LEFT)
        self.interval_var = ttk.Entry(auto_frame, width=8)
        self.interval_var.insert(0, "1000")
        self.interval_var.pack(side=tk.LEFT, padx=2)
        self.auto_send = tk.BooleanVar()
        self.auto_send_cb = tk.Checkbutton(auto_frame, text="自动发送", variable=self.auto_send,
                                           command=self.toggle_auto_send)
        self.auto_send_cb.pack(side=tk.LEFT)
        self.auto_send.trace_add('write',
                                 lambda *args: self.update_checkbutton_bg(self.auto_send_cb, self.auto_send))

        button_frame = ttk.Frame(frame)
        button_frame.grid(row=3, column=0, sticky="ew", pady=1)
        ttk.Button(button_frame, text="发送", command=self.send_data).pack(side=tk.LEFT)
        self.extension_btn = ttk.Button(button_frame, text="更多 >>", command=self.toggle_extension)
        self.extension_btn.pack(side=tk.RIGHT)

    def choose_color(self, direction):
        chinese_dir = "接收" if direction == "recv" else "发送"
        color = colorchooser.askcolor(title=f'选择{chinese_dir}颜色')[1]
        if color:
            if direction == 'recv':
                self.recv_color = color
                self.recv_color_lbl.config(bg=color)
            else:
                self.send_color = color
                self.send_color_lbl.config(bg=color)

    def update_checkbutton_bg(self, checkbutton, var):
        checkbutton.config(bg='yellow' if var.get() else self.default_bg)

    def send_file(self):
        if not self.serial_port or not self.serial_port.is_open:
            messagebox.showwarning("警告", "请先打开串口")
            return

        file_path = filedialog.askopenfilename()
        if not file_path: return

        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            if self.hex_send.get():
                hex_str = data.hex()
                data = binascii.unhexlify(hex_str)

            data = self.add_checksum(data)
            self.serial_port.write(data)
            self.tx_counter += len(data)
            self.display_data(data, 'send')
            self.update_counters()
        except Exception as e:
            messagebox.showerror("发送文件错误", str(e))

    def validate_hex(self, input_str):
        errors = []
        valid_chars = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', ' '}
        has_content = False

        illegal_positions = []
        for idx, char in enumerate(input_str):
            lower_char = char.lower()
            if lower_char in valid_chars:
                if lower_char != ' ':
                    has_content = True
            else:
                illegal_positions.append((idx + 1, char))

        if illegal_positions:
            error_msg = "发现非法字符：\n"
            for pos, char in illegal_positions[:3]:
                error_msg += f" 第{pos}个字符 '{char}'"
            if len(illegal_positions) > 3:
                error_msg += f"\n...等共{len(illegal_positions)}处非法字符"
            errors.append(error_msg)

        clean_str = input_str.replace(' ', '')
        if has_content and len(clean_str) % 2 != 0:
            errors.append("长度错误：有效HEX字符数必须为偶数（去除空格后）")
            errors.append(f"当前有效字符数：{len(clean_str)} ({clean_str})")

        return errors

    def show_hex_error(self, input_str, error_list):
        error_msg = "&#9888; HEX格式验证失败！\n\n"
        for error in error_list:
            error_msg += f"&#8226; {error}\n"

        error_msg += "\n&#9989; 正确HEX格式要求："
        error_msg += "\n   - 允许字符: 0-9, A-F (不区分大小写)"
        error_msg += "\n   - 允许用空格分隔，如: 01 A3 FF"
        error_msg += "\n   - 有效字符数必须为偶数（去除空格后）"

        sample = input_str.strip()
        if len(sample) > 40:
            display_sample = sample[:37] + "..."
        else:
            display_sample = sample or "<空输入>"

        error_msg += f"\n\n&#128221; 您的输入：\n{display_sample}"

        messagebox.showerror("HEX发送错误", error_msg)

    def save_data(self):
        content = self.text_display.get("1.0", tk.END)
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if not file_path: return

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            messagebox.showinfo("保存成功", "数据已保存至文件")
        except Exception as e:
            messagebox.showerror("保存错误", str(e))

    def add_checksum(self, data):
        checksum_type = self.checksum_combo.get()
        if checksum_type == 'None':
            return data
        elif checksum_type == 'CRC-16':
            crc = self.calculate_crc16(data)
            return data + crc
        elif checksum_type == 'XOR':
            xor = self.calculate_xor(data)
            return data + xor.to_bytes(1, 'big')
        return data

    def calculate_crc16(self, data):
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc >>= 1
                    crc ^= 0xA001
                else:
                    crc >>= 1
        return crc.to_bytes(2, 'little')

    def calculate_xor(self, data):
        xor = 0
        for byte in data:
            xor ^= byte
        return xor

    def update_ports(self):
        ports = [port.device for port in serial.tools.list_ports.comports()]
        self.port_combo['values'] = ports
        self.port_combo.set(ports[0] if ports else '')

    def update_status(self, status, success=True):
        if success:
            conn_info = f"{self.port_combo.get()} | {self.baud_combo.get()}波特 | {self.data_bits.get()}数据位 | "
            conn_info += f"{self.stop_bits.get()}停止位 | {self.parity.get()} | {self.flow_control.get()}"
            self.status_conn.config(text=conn_info, foreground='green')
        else:
            self.status_conn.config(text=status, foreground='red')

    def update_counters(self):
        self.status_rx.config(text=f"RX:{self.rx_counter}")
        self.status_tx.config(text=f"TX:{self.tx_counter}")

    def clear_display(self):
        self.text_display.config(state=tk.NORMAL)
        self.text_display.delete(1.0, tk.END)
        self.text_display.config(state=tk.DISABLED)
        self.rx_counter = self.tx_counter = 0
        self.update_counters()

    def start_loop_send(self):
        if not self.loop_send_active:
            return

        commands = []
        for cmd in self.preset_commands.commands:
            order = cmd['widgets']['order_entry'].get()
            if order.isdigit() and int(order) > 0:
                commands.append({
                    'order': int(order),
                    'delay': int(cmd['widgets']['delay_entry'].get()),
                    'command': cmd['widgets']['command_entry'].get(),
                    'hex': cmd['widgets']['hex_var'].get()
                })

        if not commands:
            messagebox.showwarning("提示", "没有配置有效发送指令")
            self.preset_commands.loop_send_var.set(False)
            return

        self._send_sequence(sorted(commands, key=lambda x: x['order']))

    def _send_sequence(self, commands, index=0):
        if not self.loop_send_active or index >= len(commands):
            return

        cmd = commands[index]
        try:
            data = self._prepare_command_data(cmd['command'], cmd['hex'])
            data = self.add_checksum(data)
            self._execute_send(data)

            if index + 1 < len(commands):
                next_delay = cmd['delay']
                self.master.after(next_delay, self._send_sequence, commands, index + 1)
            else:
                self.master.after(commands[-1]['delay'], self.start_loop_send)
        except Exception as e:
            messagebox.showerror("发送错误", f"指令发送失败：{str(e)}")
            self.preset_commands.loop_send_var.set(False)

    def toggle_loop_send(self):
        if self.preset_commands.loop_send_var.get():
            if not self.serial_port or not self.serial_port.is_open:
                messagebox.showwarning("警告", "请先打开串口")
                self.preset_commands.loop_send_var.set(False)
                return
            self.loop_send_active = True
            self.start_loop_send()
        else:
            self.loop_send_active = False

    def toggle_auto_send(self):
        self.auto_send_flag = self.auto_send.get()
        if self.auto_send_flag:
            self.auto_send_loop()

    def auto_send_loop(self):
        if self.auto_send_flag and self.serial_port.is_open:
            self.send_data()
            self.master.after(max(100, int(self.interval_var.get())), self.auto_send_loop)

    def on_port_change(self, event):
        if self.serial_port and self.serial_port.is_open:
            self.close_serial()
            self.open_serial()

    def toggle_serial(self):
        if self.serial_port and self.serial_port.is_open:
            self.close_serial()
        else:
            self.open_serial()

    def open_serial(self):
        try:
            params = {
                'port': self.port_combo.get(),
                'baudrate': int(self.baud_combo.get()),
                'bytesize': int(self.data_bits.get()),
                'stopbits': {'1': 1, '1.5': 1.5, '2': 2}[self.stop_bits.get()],
                'parity': {'无': 'N', '奇校验': 'O', '偶校验': 'E'}[self.parity.get()],
                'xonxoff': 1 if self.flow_control.get() == 'XON/XOFF' else 0,
                'rtscts': 1 if self.flow_control.get() == 'RTS/CTS' else 0
            }
            self.serial_port = serial.Serial(**params)
            self.open_btn.config(text="关闭端口")
            self.update_status("", True)
            self.receive_flag.set()
            Thread(target=self.receive_data, daemon=True).start()
            self.save_serial_settings()
            self.update_status("", True)
        except Exception as e:
            self.update_status(f"连接失败：{str(e)}", False)

    def save_serial_settings(self):
        config = configparser.ConfigParser()
        config.read(self.config_file, encoding='utf-8')

        if not config.has_section('SerialSettings'):
            config.add_section('SerialSettings')

        config.set('SerialSettings', 'port', self.port_combo.get())
        config.set('SerialSettings', 'baudrate', self.baud_combo.get())
        config.set('SerialSettings', 'databits', self.data_bits.get())
        config.set('SerialSettings', 'stopbits', self.stop_bits.get())
        config.set('SerialSettings', 'parity', self.parity.get())
        config.set('SerialSettings', 'flowcontrol', self.flow_control.get())

        config.set('SerialSettings', 'hex_send', str(self.hex_send.get()))
        config.set('SerialSettings', 'hex_display', str(self.hex_display.get()))
        config.set('SerialSettings', 'timestamp', str(self.timestamp.get()))
        config.set('SerialSettings', 'checksum', self.checksum_combo.get())
        config.set('SerialSettings', 'recv_color', self.recv_color)
        config.set('SerialSettings', 'send_color', self.send_color)

        with open(self.config_file, 'w', encoding='utf-8') as f:
            config.write(f)

    def load_serial_settings(self):
        config = configparser.ConfigParser()
        config.read(self.config_file, encoding='utf-8')

        if not config.has_section('SerialSettings'):
            return

        def safe_get(option, default):
            return config.get('SerialSettings', option, fallback=default)

        saved_port = safe_get('port', '')
        if saved_port in self.port_combo['values']:
            self.port_combo.set(saved_port)

        self.baud_combo.set(safe_get('baudrate', '9600'))
        self.data_bits.set(safe_get('databits', '8'))
        self.stop_bits.set(safe_get('stopbits', '1'))
        self.parity.set(safe_get('parity', '无'))
        self.flow_control.set(safe_get('flowcontrol', '无'))

        self.hex_send.set(config.getboolean('SerialSettings', 'hex_send', fallback=False))
        self.hex_display.set(config.getboolean('SerialSettings', 'hex_display', fallback=False))
        self.timestamp.set(config.getboolean('SerialSettings', 'timestamp', fallback=True))
        self.checksum_combo.set(safe_get('checksum', 'None'))
        self.on_checksum_selected(None)

        self.recv_color = safe_get('recv_color', '#000000')
        self.send_color = safe_get('send_color', '#0000FF')
        self.recv_color_lbl.config(bg=self.recv_color)
        self.send_color_lbl.config(bg=self.send_color)

    def close_serial(self):
        self.receive_flag.clear()
        if self.serial_port:
            self.serial_port.close()
        self.open_btn.config(text="打开端口")
        self.status_conn.config(text="未连接", foreground='black')

    def receive_data(self):
        while self.receive_flag.is_set():
            try:
                self._check_buffer_timeout()

                if self.serial_port.in_waiting:
                    data = self.serial_port.read(self.serial_port.in_waiting)
                    self._process_incoming_data(data)

                time.sleep(0.001)
            except Exception as e:
                print("接收错误:", e)
                self.receive_flag.clear()
                break

    def _process_incoming_data(self, data):
        self.receive_buffer.extend(data)
        self.last_receive_time = time.time()

        while len(self.receive_buffer) >= self.min_frame_length:
            if self._check_modbus_frame():
                return

            if b'\x0A' in self.receive_buffer:
                pos = self.receive_buffer.find(b'\x0A') + 1
                self._commit_frame(pos)
                return

            break

    def _check_buffer_timeout(self):
        if len(self.receive_buffer) == 0:
            return

        if (time.time() - self.last_receive_time > self.frame_timeout) or \
                (len(self.receive_buffer) >= self.max_frame_length):
            self._commit_frame(len(self.receive_buffer))

    def _check_modbus_frame(self):
        if len(self.receive_buffer) < 4:
            return False

        start_address = self.receive_buffer[0]
        if start_address not in range(0x00, 0xFF + 1):
            return False

        function_code = self.receive_buffer[1]
        valid_func_codes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x10]
        if function_code not in valid_func_codes:
            return False

        expected_length = {
            0x01: 6 + (self.receive_buffer[2] // 8) + 3,
            0x03: 5 + 2 * self.receive_buffer[2],
            0x04: 5 + 2 * self.receive_buffer[2],
            0x05: 6,
            0x06: 6,
            0x10: 7 + 2 * ((self.receive_buffer[4] * 2) - 1)
        }.get(function_code, 8)

        if len(self.receive_buffer) < expected_length:
            return False

        crc_received = self.receive_buffer[-2:]
        crc_calculated = self.calculate_crc16(self.receive_buffer[:-2])
        if crc_received == crc_calculated:
            self._commit_frame(expected_length)
            return True

        return False

    def _commit_frame(self, length):
        packet = bytes(self.receive_buffer[:length])
        del self.receive_buffer[:length]

        self.rx_counter += len(packet)
        self.display_data(packet, 'recv')
        self.update_counters()

        self.auto_reply_handler.check_and_reply(packet)

    def calculate_crc16(self, data):
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc >>= 1
                    crc ^= 0xA001
                else:
                    crc >>= 1
        return crc.to_bytes(2, 'little')

    def send_data(self):
        if not (self.serial_port and self.serial_port.is_open):
            messagebox.showwarning("警告", "请先打开串口")
            return

        raw_text = self.send_text.get("1.0", tk.END).strip()
        if not raw_text:
            return

        try:
            if self.hex_send.get():
                error_list = self.validate_hex(raw_text)
                if error_list:
                    self.show_hex_error(raw_text, error_list)
                    return

                hex_str = raw_text.replace(' ', '')
                if len(hex_str) % 2 != 0:
                    messagebox.showerror("格式错误", "HEX长度必须为偶数")
                    return

                try:
                    data = binascii.unhexlify(hex_str)
                except binascii.Error as e:
                    messagebox.showerror("HEX解析错误", f"无效的HEX格式: {str(e)}")
                    return
            else:
                data = raw_text.encode('gbk')

            data_with_checksum = self.add_checksum(data)
            self.serial_port.write(data_with_checksum)
            self.tx_counter += len(data_with_checksum)
            self.update_counters()
            if self.hex_send.get():
                display_cmd = ' '.join(f'{b:02X}' for b in data)
            else:
                display_cmd = raw_text
            self.history_handler.add_history(display_cmd, self.hex_send.get())

            self.display_data(data_with_checksum, 'send')
        except Exception as e:
            error_msg = f"发送失败: {str(e)}"
            if isinstance(e, serial.SerialException):
                error_msg += "\n请检查串口连接状态"
            messagebox.showerror("发送错误", error_msg)

    def send_custom_command(self, command, hex_mode):
        if not self.serial_port or not self.serial_port.is_open:
            messagebox.showwarning("警告", "请先打开串口")
            return

        if not command.strip():
            messagebox.showwarning("提示", "指令内容不能为空")
            return

        try:
            if hex_mode:
                clean_command = command.replace(' ', '')
                error_list = self.validate_hex(clean_command)
                if error_list:
                    self.show_hex_error(command, error_list)
                    return

                try:
                    data = binascii.unhexlify(clean_command)
                except binascii.Error as e:
                    messagebox.showerror("HEX解析错误",
                                         f"无效的HEX数据: {str(e)}\n"
                                         f"原始输入: {command[:50]}{'...' if len(command) > 50 else ''}")
                    return
            else:
                data = command.encode('gbk')
            data_with_checksum = self.add_checksum(data)
            self.serial_port.write(data_with_checksum)
            self.tx_counter += len(data_with_checksum)
            self.update_counters()
            self.history_handler.add_history(command, hex_mode)
            self.display_data(data_with_checksum, 'send')
        except Exception as e:
            error_type = "硬件错误" if isinstance(e, serial.SerialException) else "程序错误"
            error_msg = f"{error_type}: {str(e)}"
            if isinstance(e, serial.SerialException):
                error_msg += "\n可能原因：串口断开连接或设备无响应"
            messagebox.showerror("发送失败", error_msg)

    def _prepare_command_data(self, command, hex_mode):
        if hex_mode:
            hex_str = command.replace(' ', '')
            return binascii.unhexlify(hex_str)

        return command.encode('utf-8')

    def _execute_send(self, data):
        self.serial_port.write(data)
        self.tx_counter += len(data)
        self.display_data(data, 'send')
        self.update_counters()

    def display_data(self, data, direction):
        prefix = "收←◆ " if direction == 'recv' else "发→◇ "
        color = self.send_color if direction == 'send' else self.recv_color

        if self.hex_display.get():
            display = ' '.join(f'{b:02X}' for b in data)
        else:
            display = self.auto_decode(data)

        if self.timestamp.get():
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            full_text = f"[{timestamp}] {prefix}{display}"
        else:
            full_text = f"{prefix}{display}"

        self.text_display.config(state=tk.NORMAL)
        self.text_display.insert(tk.END, full_text + '\n', (color,))
        self.text_display.tag_config(color, foreground=color)
        self.text_display.see(tk.END)
        self.text_display.config(state=tk.DISABLED)

    def auto_decode(self, data):
        encodings = ['utf-8', 'gb18030', 'big5', 'shift_jis', 'latin-1']
        for encoding in encodings:
            try:
                return data.decode(encoding, errors='strict')
            except UnicodeDecodeError:
                continue

        try:
            return data.decode('utf-8', errors='replace')
        except:
            return str(data)

    def create_context_menu(self):
        self.context_menu = tk.Menu(self.master, tearoff=0)
        self.context_menu.add_command(label="复制", command=self.on_copy)
        self.context_menu.add_command(label="粘贴", command=self.on_paste)
        self.context_menu.add_command(label="剪切", command=self.on_cut)

        self.context_menu.add_separator()
        self.context_menu.add_command(label="全选", command=self.on_select_all)

    def show_context_menu(self, event):
        widget = event.widget

        is_text_widget = isinstance(widget, tk.Text)
        is_entry_widget = isinstance(widget, ttk.Entry)
        is_readonly = False

        if is_text_widget:
            is_readonly = widget.cget('state') == 'disabled'
        elif is_entry_widget:
            is_readonly = widget.cget('state') == 'disabled'

        self.context_menu.entryconfig("剪切",
                                      state="normal" if (not is_readonly) and (
                                                  widget != self.text_display) else "disabled")
        self.context_menu.entryconfig("粘贴",
                                      state="normal" if not is_readonly else "disabled")

        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def on_copy(self):
        widget = self.master.focus_get()
        if isinstance(widget, tk.Text):
            try:
                widget.clipboard_clear()
                text = widget.get(tk.SEL_FIRST, tk.SEL_LAST)
                widget.clipboard_append(text)
            except tk.TclError:
                pass
        elif isinstance(widget, ttk.Entry):
            widget.event_generate("<<Copy>>")

    def on_paste(self):
        widget = self.master.focus_get()
        if isinstance(widget, tk.Text):
            widget.insert(tk.INSERT, widget.clipboard_get())
        elif isinstance(widget, ttk.Entry):
            widget.event_generate("<<Paste>>")

    def on_cut(self):
        widget = self.master.focus_get()
        if isinstance(widget, tk.Text) and widget != self.text_display:
            try:
                widget.clipboard_clear()
                text = widget.get(tk.SEL_FIRST, tk.SEL_LAST)
                widget.clipboard_append(text)
                widget.delete(tk.SEL_FIRST, tk.SEL_LAST)
            except tk.TclError:
                pass
        elif isinstance(widget, ttk.Entry):
            widget.event_generate("<<Cut>>")

    def on_select_all(self):
        widget = self.master.focus_get()
        if isinstance(widget, tk.Text):
            widget.tag_add(tk.SEL, "1.0", tk.END)
            widget.mark_set(tk.INSERT, "1.0")
            widget.see(tk.INSERT)
        elif isinstance(widget, ttk.Entry):
            widget.select_range(0, tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    app = SerialDebugger(root)
    root.mainloop()