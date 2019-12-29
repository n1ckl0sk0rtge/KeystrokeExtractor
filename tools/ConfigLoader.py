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

    def get_ipversion(self):
        return self.conf[0].text

    def get_port(self):
        return int(self.conf[1].text)

    def get_inputphrase(self):
        return str(self.conf[2].text)

    def get_start_package_ranges(self):
        if self.system == "desktop":
            conf = list()
            for e in self.start_package_ranges[0]:
                conf.append(e)
            return conf
        elif self.system == "mobile":
            return self.start_package_ranges
        else:
            self.throw_error("system", self.system)

    def get_post_package_ranges(self):
        if self.system == "desktop" or self.system == "mobile":
            return self.post_package_ranges
        else:
            self.throw_error("system", self.system)

    def get_followed_package_ranges(self):
        if self.system == "desktop":
            conf = list()
            for e in self.followed_package_ranges[0]:
                conf.append(e)
            return conf
        elif self.system == "mobile":
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
        print(colored("Error at " + tag + " : Config is not valid - " + str(value), "red"))







