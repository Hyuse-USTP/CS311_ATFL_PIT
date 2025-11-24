import customtkinter as ctk
import tkinter as tk
import subprocess
import threading
import json
import sys
import os

# CONFIGURATION
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

CPP_EXECUTABLE = "./pda_json" 
if sys.platform == "win32": CPP_EXECUTABLE = "pda_json.exe"

class ModernPDA(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Network Forensic Analyzer (Professional Edition)")
        self.geometry("1000x650")
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # === LEFT SIDEBAR (Controls) ===
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo = ctk.CTkLabel(self.sidebar, text="PDA PROTOCOL\nVISUALIZER", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        # Buttons
        self.btn_1 = ctk.CTkButton(self.sidebar, text="1. Web Browsing", command=lambda: self.run_cpp(1))
        self.btn_1.grid(row=1, column=0, padx=20, pady=8)

        self.btn_2 = ctk.CTkButton(self.sidebar, text="2. SSH Session", command=lambda: self.run_cpp(2))
        self.btn_2.grid(row=2, column=0, padx=20, pady=8)
        
        self.btn_3 = ctk.CTkButton(self.sidebar, text="3. Session Hijack", fg_color="#D32F2F", hover_color="#B71C1C", command=lambda: self.run_cpp(3))
        self.btn_3.grid(row=3, column=0, padx=20, pady=8)

        self.btn_4 = ctk.CTkButton(self.sidebar, text="4. Nmap Scan", fg_color="#D32F2F", hover_color="#B71C1C", command=lambda: self.run_cpp(4))
        self.btn_4.grid(row=4, column=0, padx=20, pady=8)

        # Log Box
        self.lbl_log = ctk.CTkLabel(self.sidebar, text="Action Log:", anchor="w")
        self.lbl_log.grid(row=5, column=0, padx=20, pady=(20,0), sticky="w")
        self.console = ctk.CTkTextbox(self.sidebar, width=180, height=250)
        self.console.grid(row=6, column=0, padx=10, pady=5)

        # === RIGHT AREA (Visualization) ===
        self.vis_frame = ctk.CTkFrame(self, fg_color="#1a1a1a")
        self.vis_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        
        self.vis_frame.grid_rowconfigure(0, weight=1)
        self.vis_frame.grid_columnconfigure(0, weight=1)

        # Canvas
        self.canvas = tk.Canvas(self.vis_frame, bg="#1a1a1a", highlightthickness=0)
        self.canvas.grid(row=0, column=0, sticky="nsew")

        # Analysis Panel
        self.analysis_frame = ctk.CTkFrame(self.vis_frame, height=100, fg_color="#222")
        self.analysis_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=10)
        
        self.lbl_theory = ctk.CTkLabel(self.analysis_frame, text="THEORETICAL ANALYSIS:", font=ctk.CTkFont(weight="bold", size=12), text_color="#00e5ff")
        self.lbl_theory.pack(anchor="w", padx=10, pady=(5,0))
        
        self.txt_theory = ctk.CTkLabel(self.analysis_frame, text="Ready to analyze...", font=ctk.CTkFont(family="Consolas", size=13), text_color="#ccc", wraplength=700, justify="left")
        self.txt_theory.pack(anchor="w", padx=10, pady=5)

        # Graphics Objects
        self.nodes = {}
        self.packet_obj = None
        self.packet_text_obj = None 
        self.token_obj = None
        self.token_txt = None
        
        self.draw_scene()

    def draw_scene(self):
        # Draw Stack Box (Background)
        self.canvas.create_text(700, 180, text="STACK MEMORY", fill="#aaa", font=("Roboto", 10))
        self.canvas.create_rectangle(660, 200, 740, 350, outline="#777", width=2)
        
        # Base Z0
        self.canvas.create_rectangle(665, 320, 735, 345, fill="#444", outline="")
        self.canvas.create_text(700, 332, text="Z0", fill="white")
        
        # Session Token (Created hidden)
        self.token_obj = self.canvas.create_rectangle(665, 290, 735, 315, fill="#1f538d", outline="")
        self.token_txt = self.canvas.create_text(700, 302, text="SESSION", fill="white")
        self.canvas.itemconfigure(self.token_obj, state='hidden')
        self.canvas.itemconfigure(self.token_txt, state='hidden')

        # Draw Nodes
        coords = {0: (100, 250), 1: (300, 250), 2: (500, 250), 3: (300, 450)}
        labels = {0: "q0\nListen", 1: "q1\nActive", 2: "q2\nClosed", 3: "TRAP\nReject"}
        
        # Lines
        self.canvas.create_line(140, 250, 260, 250, fill="#555", width=3, arrow=tk.LAST)
        self.canvas.create_line(340, 250, 460, 250, fill="#555", width=3, arrow=tk.LAST)
        self.canvas.create_line(300, 290, 300, 410, fill="#500", width=2, dash=(4,2), arrow=tk.LAST) 

        for i, pos in coords.items():
            x, y = pos
            color = "#333"
            outline = "#555"
            if i == 3: outline = "#D32F2F"
            self.nodes[i] = self.canvas.create_oval(x-40, y-40, x+40, y+40, outline=outline, width=3, fill=color)
            self.canvas.create_text(x, y, text=labels[i], fill="white", font=("Roboto", 10, "bold"))

    def update_ui(self, data):
        if data['type'] == 'init':
            self.console.delete("0.0", "end")
            self.console.insert("0.0", f"{data['desc']}\n")
            return

        state = data['state']
        pkt = data['packet']
        desc = data['desc']
        analysis = data['analysis']
        stack_top = data['stackTop']
        is_attack = data['isAttack']
        
        # 1. Log & Analysis
        if pkt: self.console.insert("end", f"[{pkt}] {desc}\n")
        self.console.see("end")
        self.txt_theory.configure(text=analysis)

        # 2. Nodes Highlight
        for i, node_id in self.nodes.items():
            base_col = "#333"
            out_col = "#555"
            if i == 3: out_col = "#D32F2F"
            self.canvas.itemconfig(node_id, fill=base_col, outline=out_col)
        
        active_col = "#1f538d" # Blue
        if is_attack: active_col = "#D32F2F" # Red
        self.canvas.itemconfig(self.nodes[state], fill=active_col, outline="white")

        # 3. Stack Visualization (UPDATED LOGIC)
        # We now check if "S" is present in the string, handling "S" or "Session Token"
        if "S" in stack_top or "SESSION" in stack_top:
            self.canvas.itemconfigure(self.token_obj, state='normal')
            self.canvas.itemconfigure(self.token_txt, state='normal')
            # Force to top so it's not hidden by background redraws
            self.canvas.tag_raise(self.token_obj)
            self.canvas.tag_raise(self.token_txt)
        else:
            self.canvas.itemconfigure(self.token_obj, state='hidden')
            self.canvas.itemconfigure(self.token_txt, state='hidden')

        # 4. Packet Animation
        # Delete BOTH old box and old text
        if self.packet_obj: self.canvas.delete(self.packet_obj)
        if self.packet_text_obj: self.canvas.delete(self.packet_text_obj)

        if pkt:
            pos = self.canvas.coords(self.nodes[state])
            px, py = (pos[0]+pos[2])/2, (pos[1]+pos[3])/2
            
            col = "#FBC02D"
            if is_attack: col = "#D32F2F"
            
            # Create Packet Box
            self.packet_obj = self.canvas.create_rectangle(px-35, py-60, px+35, py-40, fill=col)
            # Create Packet Text
            self.packet_text_obj = self.canvas.create_text(px, py-50, text=pkt, fill="black", font=("Roboto", 9, "bold"))
            
            # Ensure packet is always on top of everything
            self.canvas.tag_raise(self.packet_obj)
            self.canvas.tag_raise(self.packet_text_obj)

    def run_cpp(self, scenario_id):
        # Clear packet visual on new run
        if self.packet_obj: self.canvas.delete(self.packet_obj)
        if self.packet_text_obj: self.canvas.delete(self.packet_text_obj)
        threading.Thread(target=self._thread_target, args=(scenario_id,), daemon=True).start()

    def _thread_target(self, scenario_id):
        try:
            # bufsize=1 enables line-buffering for real-time updates
            proc = subprocess.Popen([CPP_EXECUTABLE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            proc.stdin.write(f"{scenario_id}\n")
            proc.stdin.flush()

            for line in proc.stdout:
                if not line: break
                try:
                    data = json.loads(line.strip())
                    self.after(0, self.update_ui, data)
                except json.JSONDecodeError: pass

            proc.wait()
        except FileNotFoundError:
            self.after(0, lambda: self.console.insert("end", "Error: C++ Executable not found. Compile pda_json.cpp first.\n"))

if __name__ == "__main__":
    app = ModernPDA()
    app.mainloop()