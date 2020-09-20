import sys
import xml.etree.ElementTree as xmlparser
from termcolor import colored


class Config:

    def __init__(self, file):
        self.conf_file = file
        self.conf = xmlparser.parse(file).getroot()

        self.system = self.conf[3].text

        self.start_package_ranges = list()
        self.post_package_ranges = list()
        self.followed_package_ranges = list()
        self.window_to_next_package = 0
        self.fautly_stream_counter = 0
        self.extract_window_conf()

    def is_desktop(self):
        if self.conf[3].text == "desktop":
            return True
        else:
            return False

    def is_mobile(self):
        if self.conf[3].text == "ios" or self.conf[3].text == "android":
            return True
        else:
            return False

    def is_ios(self):
        if self.conf[3].text == "ios":
            return True
        else:
            return False

    def is_android(self):
        if self.conf[3].text == "android":
            return True
        else:
            return False

    def is_vpn(self):
        if self.conf[3].text == "vpn":
            return True
        else:
            return False

    def get_ipversion(self):
        return self.conf[0].text

    def port_validation(self, port):
        if self.is_desktop() or self.is_mobile():
            return bool(int(self.conf[1].text) == port)
        elif self.is_vpn():
            p_range_list = [int(e) for e in self.conf[1].text.split("-")]
            return bool(port in range(p_range_list[0], p_range_list[1]))

    def get_inputphrase(self):
        if self.conf[2].text is None:
            return None
        else:
            return str(self.conf[2].text)

    def get_start_package_ranges(self):
        if self.is_desktop() or self.is_vpn():
            conf = list()
            for e in self.start_package_ranges[0]:
                conf.append(e)
            return conf
        elif self.is_mobile():
            return self.start_package_ranges
        else:
            self.throw_error("system", self.system)

    def get_post_package_ranges(self):
        if self.is_desktop() or self.is_mobile() or self.is_vpn():
            return self.post_package_ranges
        else:
            self.throw_error("system", self.system)

    def get_followed_package_ranges(self):
        if self.is_desktop() or self.is_vpn():
            conf = list()
            for e in self.followed_package_ranges[0]:
                conf.append(e)
            return conf
        elif self.is_mobile():
            return self.followed_package_ranges
        else:
            self.throw_error("system", self.system)

    def get_window_to_next_package(self):
        return self.window_to_next_package

    def extract_window_conf(self):
        def find_tag(root, tag):
            for child in root:
                if child.tag == tag:
                    return child

        window_conf = find_tag(self.conf, "windows")

        start_package_conf = find_tag(window_conf, "start_package_ranges")
        for ranges in start_package_conf:
            self.start_package_ranges.append([int(e) for e in ranges.text.split("-")])

        post_package_conf = find_tag(window_conf, "post_package_range")
        self.post_package_ranges = [int(e) for e in post_package_conf.text.split("-")]

        followed_package_conf = find_tag(window_conf, "followed_package_ranges")
        for ranges in followed_package_conf:
            self.followed_package_ranges.append([int(e) for e in ranges.text.split("-")])

        window_to_next_conf = find_tag(window_conf, "window_to_next_package")
        self.window_to_next_package = int(window_to_next_conf.text)

        fautly_stream_counter_conf = find_tag(self.conf, "fautly_stream_counter")
        self.fautly_stream_counter = int(fautly_stream_counter_conf.text)

    def throw_error(self, tag, value):
        print(colored(("Error at " + tag + " : Config is not valid - " + str(value), "red")))
        sys.exit(("Error at " + tag + " : Config is not valid - " + str(value), "red"))







