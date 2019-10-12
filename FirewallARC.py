print("Loading...")
import Interface
import Sniffer
import Filter
from threading import Thread
import socket
import re
import os


print("---------------------------------------------\n"
      "| Welcome to FirewallARC, a Supinfo project |\n"
      "---------------------------------------------")


class Firewall(Thread):  # Command prompt
    """Command prompt class"""

    interfacelink = []
    cmdlink = []
    program = {"firewall": Sniffer.sniffer(interfacelink, cmdlink), "interface": Interface.Interface(interfacelink)}

    def __init__(self):
        Thread.__init__(self)

    def run(self):  # command management
        running = True
        while running:
            command = input(os.environ['USERNAME'] + ">")
            if command == "start firewall":
                if not self.program["firewall"].is_alive():
                    running = False
                    cmd = Firewall()
                    print("Start...")
                    self.program["firewall"].running = True
                    self.program["firewall"].start()
                    print("Firewall ON")
                    cmd.start()
                else:
                    print("Firewall is already running")
            elif command == "start interface":
                if not self.program["interface"].is_alive():
                    running = False
                    cmd = Firewall()
                    print("Start...")
                    self.program["interface"] = Interface.Interface(self.interfacelink)
                    self.program["interface"].running = True
                    self.program["interface"].start()
                    print("Interface ON")
                    cmd.start()
                else:
                    print("Interface is already running")
            elif command == "stop firewall":
                if self.program["firewall"].is_alive():
                    print("Shutdown...")
                    self.program["firewall"].running = False
                    self.program["firewall"].join()
                    print("Firewall OFF")
                    self.program["firewall"] = Sniffer.sniffer(self.interfacelink, self.cmdlink)
                else:
                    print("Firewall is already shutdown")
            elif command == "stop interface":
                if self.program["interface"].is_alive():
                    print("Shutdown...")
                    self.program["interface"].running = False
                    self.program["interface"].join()
                    print("Interface OFF")
                else:
                    print("Interface is already shutdown")
            elif command == "show rules":
                configuration = Filter.loadconf()
                for rules in configuration:
                    print(" ", configuration.index(rules) + 1, "- ", end="")
                    for rule in rules:
                        print(rule, ":", rules[rule], end=" | ")
                    print("")
            elif command[0:8] == "add rule":
                if re.match("^([a-z]+: ([a-z]|[A-Z]|[0-9]|[.])+, )*[a-z]+: ([a-z]|[A-Z]|[0-9]|[.])+$", command[9:]) != None:
                    file = open("FirewallARC.conf", "a")
                    file.write(command[9:] + "\n")
                    file.close()
                    print("Done")
                else:
                    print("Pattern for the new rule proprieties not correct", command[9:])
            elif command[0:11] == "delete rule":
                configuration = Filter.loadconf()
                try:
                    configuration.pop(int(command[12:]) - 1)
                    capturesave = ""
                    for rules in configuration:
                        for rule in rules:
                            if rule != "action" and rule != "id" and rules[rule] != "":
                                capturesave += str(rule) + ": " + str(rules[rule]) + ", "
                        capturesave = capturesave[0:-2] + "\n"
                    capturefile = open("FirewallARC.conf", "w")
                    capturefile.write(capturesave)
                    capturefile.close()
                    print("Done")
                except:
                    print("Invalid rule index")
            elif command[:9] == "read file":
                try:
                    Interface.rdpcap(command[10:]).summary()
                except:
                    print("Wrong type detected. Please select a pcap file.")
            elif command[0:3] == "ban":
                try:
                    file = open("FirewallARC.conf", "a")
                    file.write("ipsrc: " + socket.gethostbyname(command[4:]) + "\n")
                    file.close()
                    print("Done")
                except:
                    print("Hostname not found")
            elif command[0:5] == "unban":
                try:
                    ip = socket.gethostbyname(command[6:])
                    configuration = Filter.loadconf()
                    for rules in configuration:
                        if len(rules) == 1 and "ipsrc" in rules and rules["ipsrc"] == ip:
                            configuration.pop(configuration.index(rules))
                    capturesave = ""
                    for rules in configuration:
                        for rule in rules:
                            if rule != "action" and rule != "id" and rules[rule] != "":
                                capturesave += str(rule) + ": " + str(rules[rule]) + ", "
                        capturesave = capturesave[0:-2] + "\n"
                    capturefile = open("FirewallARC.conf", "w")
                    capturefile.write(capturesave)
                    capturefile.close()
                    print("Done")
                except:
                    print("Hostname not found")
            elif command == "show status":
                print("- firewall", "ON" if self.program["firewall"].is_alive() else "OFF")
                print("- interface", "ON" if self.program["interface"].is_alive() else "OFF")
            elif command[0:12] == "show packets":
                index = 0
                if len(command) > 12 and not re.match("^([a-z]+: ([a-z]|[A-Z]|[0-9]|[.])+, )*[a-z]+: ([a-z]|[A-Z]|[0-9]|[.])+$", command[13:]):
                    print("Argument doesn't respect the pattern")
                for rules in self.cmdlink:
                    tmp = ""
                    for rule in rules:
                        tmp += rule + ": " + rules[rule] + " | "
                    if len(command) > 12 and re.match("^([a-z]+: ([a-z]|[A-Z]|[0-9]|[.])+, )*[a-z]+: ([a-z]|[A-Z]|[0-9]|[.])+$", command[13:]):
                        myrules = command[13:].split(", ")
                        show = True
                        for myrule in myrules:
                            if myrule not in tmp:
                                show = False
                        if show:
                            index += 1
                            print(" ", index, "- ", end="")
                            print(tmp)
                    elif len(command) < 13:
                        index += 1
                        print(" ", index, "- ", end="")
                        print(tmp)
            elif command == "exit":
                running = False
                print("Shutdown interface...")
                if self.program["interface"].is_alive():
                    self.program["interface"].running = False
                    self.program["interface"].join()
                print("Interface OFF")
                print("Shutdown firewall...")
                if self.program["firewall"].is_alive():
                    self.program["firewall"].running = False
                    self.program["firewall"].join()
                print("Firewall OFF")
            elif command == "man":
                print("- start firewall\n"
                      "- start interface\n"
                      "- stop firewall\n"
                      "- stop interface\n"
                      "- ban <host name>\n"
                      "- unban <host name>\n"
                      "- add rule <rule.s>\n"
                      "- delete rule <index>\n"
                      "- read file <path>\n"
                      "- man\n"
                      "- show rules\n"
                      "- show status\n"
                      "- show packets (<rule: value, rule: value...>)\n"
                      "- exit")
            else:
                print("Unknown command. Use man command.")


firewall = Firewall()
firewall.run()
