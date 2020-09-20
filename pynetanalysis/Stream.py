from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from pynetanalysis import ExtendedPackage as ePackage
from termcolor import colored


class Stream:

    def __init__(self, package, keystroke):
        try:
            self.source_ip = package[IPv6].src
        except:
            self.source_ip = package[IP].src

        self.packages = list()
        self.add_package_to_stream(package, keystroke)

        self.data_limiter = 9
        self.faulty = False
        self.package_counter = 0
        print("New source IP found -> " + self.source_ip)

    def add_package_to_stream(self, package, keystroke):
        e_package = ePackage.ExtendedPackage(package)
        e_package.keystroke = keystroke
        self.packages.append(e_package)

    def set_as_faulty(self):
        self.faulty = True

    def is_faulty(self, phrase):
        if phrase is not None:
            if len(self.packages) < len(phrase) or self.faulty:
                return True
        else:
            return False

    def ip_version_check(self):
        if len(self.source_ip) > 16:
            return IPv6
        else:
            return IP

    def to_list(self):
        l = list()
        for i in range(1, len(self.packages)):
            l.append(float(self.packages[i].time) - float(self.packages[i-1].time))
        return l

    def to_arff_format(self):
        line = str()
        for e in self.to_list():
            line += str(e) + ", "
        line += str(self.source_ip) + "\n"
        return line

    def log(self, keystroke, package_id, package, phrase):
        if phrase is not None:
            if keystroke == str(phrase[len(self.packages) - 1]):
                print(keystroke + ' : ' + str(package_id) + ' length:=' + str(len(package)) + ' src=' + str(self.source_ip))
            else:
                self.set_as_faulty()
                c = colored(keystroke + ' : ' + str(package_id) + ' length:=' + str(len(package)) + ' src=' + str(self.source_ip), 'red')
                print(c)
        else:
            print(keystroke + ' : ' + str(package_id) + ' length:=' + str(len(package)) + ' src=' + str(self.source_ip))

    def create_dictionary(self):
        string = str()
        for i in range(1, len(self.packages)):
            time = str(float(self.packages[i].time) - float(self.packages[i - 1].time))
            keystrokes = self.packages[i - 1].keystroke + self.packages[i].keystroke
            string += keystrokes + " : " + time + "\n"

        return string
