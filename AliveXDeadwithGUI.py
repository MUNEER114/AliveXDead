import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import concurrent.futures
from datetime import datetime
import threading

class DomainChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("Domain Checker")
        self.root.geometry("600x400")
        
        # Domain input
        self.input_frame = ttk.Frame(root, padding="10")
        self.input_frame.pack(fill=tk.X)
        
        self.domain_entry = ttk.Entry(self.input_frame)
        self.domain_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        
        self.add_btn = ttk.Button(self.input_frame, text="Add Domain", command=self.add_domain)
        self.add_btn.pack(side=tk.LEFT)
        
        # Buttons frame
        self.btn_frame = ttk.Frame(root, padding="10")
        self.btn_frame.pack(fill=tk.X)
        
        self.load_btn = ttk.Button(self.btn_frame, text="Load from File", command=self.load_file)
        self.load_btn.pack(side=tk.LEFT, padx=5)
        
        self.check_btn = ttk.Button(self.btn_frame, text="Check Domains", command=self.start_check)
        self.check_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(self.btn_frame, text="Clear All", command=self.clear_all)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Results area
        self.results_frame = ttk.Frame(root, padding="10")
        self.results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create Treeview
        self.tree = ttk.Treeview(self.results_frame, columns=('Domain', 'Status'), show='headings')
        self.tree.heading('Domain', text='Domain')
        self.tree.heading('Status', text='Status')
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add scrollbar
        self.scrollbar = ttk.Scrollbar(self.results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        
        # Progress bar
        self.progress = ttk.Progressbar(root, mode='determinate')
        self.progress.pack(fill=tk.X, padx=10, pady=5)
        
    def add_domain(self):
        domain = self.domain_entry.get().strip()
        if domain:
            self.tree.insert('', tk.END, values=(domain, 'Pending'))
            self.domain_entry.delete(0, tk.END)
    
    def load_file(self):
        filename = filedialog.askopenfilename(
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'r') as f:
                    domains = [line.strip() for line in f if line.strip()]
                    for domain in domains:
                        self.tree.insert('', tk.END, values=(domain, 'Pending'))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def ping_domain(self, domain):
        try:
            output = subprocess.run(['ping', '-n', '1', domain], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            return domain, "Alive" if output.returncode == 0 else "Dead"
        except:
            return domain, "Dead"
    
    def check_domains(self):
        domains = [self.tree.item(item)['values'][0] for item in self.tree.get_children()]
        total = len(domains)
        self.progress['maximum'] = total
        
        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.ping_domain, domain) for domain in domains]
            completed = 0
            
            for future in concurrent.futures.as_completed(futures):
                domain, status = future.result()
                self.tree.insert('', tk.END, values=(domain, status))
                completed += 1
                self.progress['value'] = completed
                self.root.update_idletasks()
        
        self.progress['value'] = 0
        messagebox.showinfo("Complete", "Domain checking completed!")
    
    def start_check(self):
        if not self.tree.get_children():
            messagebox.showwarning("Warning", "Please add domains first!")
            return
        threading.Thread(target=self.check_domains, daemon=True).start()
    
    def clear_all(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.progress['value'] = 0

if __name__ == "__main__":
    root = tk.Tk()
    app = DomainChecker(root)
    root.mainloop()
