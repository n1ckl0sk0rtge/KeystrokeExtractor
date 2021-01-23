# relevant to provide input data over command line args
import argparse
# import own classes saved in a folder called pynetanalysis
# Patternfinder: includes functionality to find the right packages from a given Stream
# Stream: class, that represents streams of relevant packages
# Netshark: provides functionality to extract the letter in regard to the detected package from a
# decrypted pcap-file by using pyshark
# ExtendedPackage: extends the Package-class provided by scapy with an additional member-var
# for the corresponding keystroke
# PackageBuffer: class, that represents a Buffer of packages
from pynetanalysis import PatternFinder, Stream, Netshark, ExtendedPackage, PackageBuffer
# import own classes saved in a folder called tools
# Arff: class which alles the creation of files in ARFF-format with aa given Stream of packages
# ConfigLoarder: provides functionality to load all information out of the given Conf-File
from tools import Arff, ConfigLoader
# import scapy to work with network data from pcap-file
from scapy.all import *
from scapy.layers.dns import DNSRR
from scapy.layers.inet import TCP, IP
from scapy.layers.inet6 import IPv6
# to highlight some outputs to the console
from termcolor import colored

# using parser to read all relevant files
parser = argparse.ArgumentParser(description='command line options')
parser.add_argument('--pcap', dest='pcapinput', action='store', default="", help='PCAP file to process')
parser.add_argument('--conf', dest='conf', action='store', default="", help='file that contains the configuration')
parser.add_argument('--blindmode', dest='b_mode', action='store', default=True, help='boolean, that defines if blind mode is on or off')
parser_result = parser.parse_args()

# read network data from pcap-file with scapy
packages = scapy.utils.rdpcap(parser_result.pcapinput)
# providing network data to netshark as well, allowing to extract the corresponding letters from
# decrypted traffic if available
cap = Netshark.Cap(parser_result.pcapinput)

# load config from Conf-file to variable conf
conf = ConfigLoader.Config(parser_result.conf)
ip_version = conf.get_ipversion()
input_phrase = conf.get_inputphrase()

# init variables
# holds the id of the current package, counts up
package_id = 0
# set of destination ip's by which the network traffic will be pre-filtered
destination_ip = set()
# set of detected keystroke streams (could be more than one search request in a given network traffic)
keystroke_stream = set()
# init package buffer with size 5
package_buffer = PackageBuffer.PackageBuffer(size=5)
# init reference stream with none
reference_stream = None
arff_streams = list()
arff_classes = set()
instances = 0

# adding some Google IPv6-addresses to the destination-ip set
destination_ip.add('2a00:1450:4001:809::2004')
destination_ip.add('2a00:1450:4001:818::2004')
destination_ip.add('2a00:1450:4001:815::2004')
destination_ip.add('2a00:1450:4001:808::2004')
destination_ip.add('2a00:1450:4001:817::2004')
destination_ip.add('2a00:1450:4001:81c::2004')


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


# this function is called to save a detected and terminated stream
def save_stream(stream):
    global arff_classes, arff_streams, instances
    if not stream.is_faulty(input_phrase) or parser_result.b_mode is True:
        instances += 1
        arff_streams += stream.to_arff_format()
        arff_classes.add(str(stream.source_ip))


def lookup_for_new_stream():
    global reference_stream, arff_streams, arff_classes

    if package_buffer.get_last_as_package() is not None and PatternFinder.is_new_stream(package_buffer, package, conf):
        # if there is a beginning of a new keystroke stream, no detection for new keystroke stream will be
        # performed for the next 5 packages
        if reference_stream is not None:
            if len(reference_stream.packages) <= 5:
                return False
        if not PatternFinder.is_stream_from_new_source(keystroke_stream, package) and not conf.is_vpn():
            remove_stream = [stream for stream in keystroke_stream if stream.source_ip == package[get_ip_version()].src][0]
            save_stream(remove_stream)
            keystroke_stream.remove(remove_stream)
        try:
            if conf.is_desktop():
                keystroke = cap.get_letter(package_buffer.get_last_as_package_id(), None)
            elif conf.is_vpn() or conf.is_ios():
                keystroke = cap.get_letter(package_id, None)
            elif conf.is_android():
                keystroke = cap.get_letter(package_buffer.buffer[package_buffer.p_element].id, None)
            else:
                conf.throw_error("system", conf.system)
                return False
        except:
            # retransmitted Package
            # OR
            # no rights to grab letter/keystroke from decrypted package
            if parser_result.b_mode is True:
                keystroke = "?"
            else:
                return False

        if conf.is_desktop():
            reference_stream = Stream.Stream(package_buffer.get_last_as_package(), keystroke)
            reference_stream.log(keystroke, package_buffer.get_last_as_package_id(), package_buffer.get_last_as_package(), input_phrase)
        elif conf.is_vpn():
            reference_stream = Stream.Stream(package, keystroke)
            reference_stream.log(keystroke, package_id, package, input_phrase)
        elif conf.is_android():
            reference_stream = Stream.Stream(package_buffer.buffer[package_buffer.p_element].package, keystroke)
            reference_stream.log(keystroke, package_buffer.buffer[package_buffer.p_element].id, package_buffer.buffer[package_buffer.p_element].package, input_phrase)
            for i in range(package_buffer.p_element + 1, len(package_buffer)):
                keystroke = cap.get_letter(package_buffer.buffer[i].id, reference_stream)
                reference_stream.add_package_to_stream(package_buffer.buffer[i].package, keystroke)
                reference_stream.log(keystroke, package_buffer.buffer[i].id, package_buffer.buffer[i].package, input_phrase)
            if PatternFinder.is_next_package(reference_stream, package_buffer, package, conf):
                keystroke = cap.get_letter(package_id, reference_stream)
                reference_stream.add_package_to_stream(package, keystroke)
                reference_stream.log(keystroke, package_id, package, input_phrase)
        elif conf.is_ios():
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
        global reference_stream, arff_streams, arff_classes
        if current_stream.package_counter >= conf.fautly_stream_counter and not conf.b_mode:
            print(colored("remove faulty stream...", 'green'))
            keystroke_stream.remove(current_stream)
            reference_stream = None
        else:
            current_stream.package_counter += 1
        return False

    if len(current_stream.packages) == 1 and PatternFinder.is_second_package_of_stream(current_stream, package_buffer, package, conf):
        try:
            keystroke = cap.get_letter(package_id, current_stream)
        except:
            # retransmitted Package
            # OR
            # no rights to grab letter/keystroke from decrypted package
            if parser_result.b_mode is True:
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
    elif PatternFinder.is_next_package(current_stream, package_buffer, package, conf):
        try:
            keystroke = cap.get_letter(package_id, current_stream)
        except:
            # retransmitted Package
            # OR
            # no rights to grab letter/keystroke from decrypted package
            if parser_result.b is True:
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



ignore_next_package = False

# loop through all packages of the given network stream
for package in packages:
    package_id += 1
    # check if the package is a dns request: in case, add the ip to the set of destination ip
    is_dns_request(package)

    try:
        # filter by destination port, destination ip and if the package has a tcp-payload
        if package.haslayer(Raw) and conf.port_validation(package[TCP].dport) and package[get_ip_version()].dst in destination_ip:
            # look up if current package is the begin of a stream
            if not lookup_for_new_stream() and len(keystroke_stream) >= 1:
                # if not a new stream and at least on stream was detected
                lookup_for_new_package_for_current_stream()

            # adding current package to the buffer stream
            # except: special case for mobile
            if len(keystroke_stream) >= 1 and len(package) < 110 and conf.is_mobile():
                ignore_next_package = True
            elif ignore_next_package is True:
                ignore_next_package = False
            else:
                # adding current package to the buffer stream
                package_buffer.add(ExtendedPackage.ExtendedPackage(package, package_id))
    except:
        pass

while len(keystroke_stream) != 0:
    save_stream(keystroke_stream.pop())

print(colored("\nFound " + str(instances) + " streams.", "green"))
Arff.create_arff_file(parser_result.pcapinput[:-5], 0 if input_phrase is None else len(input_phrase), arff_streams, arff_classes)

