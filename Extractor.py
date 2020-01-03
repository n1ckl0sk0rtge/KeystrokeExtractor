import argparse
from pynetanalysis import PatternFinder, Stream, Netshark
from tools import Arff, ConfigLoader
from statistic import Histogram, Barchart
from scapy.all import *
from scapy.layers.dns import DNSRR
from scapy.layers.inet import TCP, IP
from scapy.layers.inet6 import IPv6
from termcolor import colored

parser = argparse.ArgumentParser(description='command line options')
parser.add_argument('--pcap', dest='pcapinput', action='store', default="/Users/nkoertge/Desktop/long_phrase_2.pcap", help='PCAP file to process')
parser.add_argument('--conf', dest='conf', action='store', default="/Users/nkoertge/Desktop/long_phrase copy.conf", help='Configfile')
parser.add_argument('--hackmode', dest='h_mode', action='store', default="False", help='')
parser_result = parser.parse_args()
packages = scapy.utils.rdpcap(parser_result.pcapinput)
cap = Netshark.Cap(parser_result.pcapinput)

conf = ConfigLoader.Config(parser_result.conf)
ip_version = conf.get_ipversion()
port = conf.get_port()
input_phrase = conf.get_inputphrase()


package_id = 0
destination_ip = set()
keystroke_stream = set()
reference_package = None
reference_package_id = 0
reference_stream = None
arff_streams = list()
arff_classes = set()
instances = 0
hist = Histogram.Histogram(normalize=True, interval=0.02)
bar = Barchart.Barchart()
dic = str()

destination_ip.add('2a00:1450:4005:803::2004')
destination_ip.add('2a00:1450:4001:818::2004')
destination_ip.add('2a00:1450:4001:808::2004')
destination_ip.add('2a00:1450:4001:817::2004')
destination_ip.add('172.217.19.67')
destination_ip.add('192.168.0.6')


def get_ip_version():
    if ip_version == "IPv6":
        return IPv6
    else:
        return IP


def is_dns_request(p_packet):
    try:
        dns_src = p_packet.an.rrname.decode('utf-8')
        if ip_version == "IPv6":
            if dns_src == 'www.google.com.' and len(p_packet[DNSRR].rdata) > 16:
                destination_ip.add(p_packet[DNSRR].rdata)
                print("DNS lookup for www.google.com completed -> " + p_packet[DNSRR].rdata)
        elif ip_version == "IP":
            if dns_src == 'www.google.com.' and len(p_packet[DNSRR].rdata) < 16:
                destination_ip.add(p_packet[DNSRR].rdata)
                print("DNS lookup for www.google.com completed -> " + p_packet[DNSRR].rdata)
    except:
        pass


def save_stream(stream):
    global arff_classes, arff_streams, instances, dic
    if not stream.is_faulty(input_phrase) or parser_result.h_mode is True:
        instances += 1
        arff_streams += stream.to_arff_format()
        arff_classes.add(str(stream.source_ip))
        # dic += stream.create_dictionary()
        # Add stream to histogram
        hist.add_data_to_histogram(stream.to_list())
        bar.add_data_to_barchart(stream.to_list())


def lookup_for_new_stream():
    global reference_stream, arff_streams, arff_classes, reference_package

    if reference_package is not None and PatternFinder.is_new_stream(reference_package, package, conf):
        # ist einmal ein Anfang gefunden, dann ignoriere für die nächsten 5 packete, ob diese auch ein neuer stream sein können
        if reference_stream is not None:
            if len(reference_stream.packages) <= 5:
                return False
        if not PatternFinder.is_stream_from_new_source(keystroke_stream, package):
            remove_stream = [stream for stream in keystroke_stream if stream.source_ip == package[get_ip_version()].src][0]
            save_stream(remove_stream)
            keystroke_stream.remove(remove_stream)
        try:
            if conf.system == "desktop":
                keystroke = cap.get_letter(reference_package_id, None)
            elif conf.system == "mobile":
                keystroke = cap.get_letter(package_id, None)
            else:
                conf.throw_error("system", conf.system)
                return False
        except:
            # Retransmitted Package
            # OR
            # No rights to grab decrypted package
            if parser_result.h_mode is True:
                keystroke = "?"
            else:
                return False

        if conf.system == "desktop":
            reference_stream = Stream.Stream(reference_package, keystroke)
            reference_stream.log(keystroke, reference_package_id, reference_package, input_phrase)
        elif conf.system == "mobile":
            reference_stream = Stream.Stream(package, keystroke)
            reference_stream.log(keystroke, package_id, package, input_phrase)
        else:
            conf.throw_error("system", conf.system)
            return False
        keystroke_stream.add(reference_stream)
        return True


def lookup_for_new_package_for_current_stream():
    current_stream = [stream for stream in keystroke_stream if stream.source_ip == package[get_ip_version()].src][0]

    def not_in_stream():
        global reference_stream, arff_streams, arff_classes, reference_package
        if current_stream.package_counter >= conf.fautly_stream_counter and len(current_stream.packages) < len(input_phrase) - 3:
                                                                            # Durch diese Bediengung wird ein gültiger Stream automatisch
                                                                            # in die Arff-Datei geschreiben, sonst händisch
            print(colored("remove faulty stream...", 'green'))
            keystroke_stream.remove(current_stream)
            reference_stream = None
        else:
            current_stream.package_counter += 1
            # print(current_stream.package_counter)
        return False

    if len(current_stream.packages) == 1 and PatternFinder.is_second_package_of_stream(current_stream, package, conf):
        try:
            keystroke = cap.get_letter(package_id, current_stream)
        except:
            # Retransmitted Package
            # OR
            # No rights to grab decrypted package
            if parser_result.h_mode is True:
                keystroke = "?"
            else:
                return not_in_stream()

        current_stream.add_package_to_stream(package, keystroke)
        current_stream.package_counter = 0
        try:
            current_stream.log(keystroke, package_id, package, input_phrase)
        except:
            current_stream.packages.remove(current_stream.packages[-1])
            return not_in_stream()
    elif PatternFinder.is_next_package(current_stream, package, conf):
        try:
            keystroke = cap.get_letter(package_id, current_stream)
        except:
            # Retransmitted Package
            # OR
            # No rights to grab decrypted package
            if parser_result.h_mode is True:
                keystroke = "?"
            else:
                return not_in_stream()

        current_stream.add_package_to_stream(package, keystroke)
        current_stream.package_counter = 0
        try:
            current_stream.log(keystroke, package_id, package, input_phrase)
        except:
            current_stream.packages.remove(current_stream.packages[-1])
            return not_in_stream()

    return not_in_stream()


for package in packages:
    package_id += 1
    is_dns_request(package)

    try:
        if package.haslayer(Raw) and package[TCP].dport == port and package[get_ip_version()].dst in destination_ip:
            # is a new stream
            if not lookup_for_new_stream() and len(keystroke_stream) >= 1:
                lookup_for_new_package_for_current_stream()

            reference_package = package
            reference_package_id = package_id
    except:
        pass

while len(keystroke_stream) != 0:
    save_stream(keystroke_stream.pop())

# plot hist
hist.plot()
bar.plot()

print(colored("\nFound " + str(instances) + " streams.", "green"))
Arff.create_arff_file(parser_result.pcapinput[:-5], len(input_phrase), arff_streams, arff_classes)

# file = open(parser_result.pcapinput.split("/")[-1][:-5] + ".dic", 'w+')
# file.write(dic)
# file.close()

