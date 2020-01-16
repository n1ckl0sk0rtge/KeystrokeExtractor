import pyshark

html_to_asci_dictionary = {"%20": " ", "%2C": ",", "%C3%A4": "ä", "%C3%BC": "ü", "%C3%9F": "ß", "%C3%B6": "ö"}


class Retransmission(Exception):
    def __init__(self, arg):
        self.args = arg


class Cap:

    def __init__(self, file):
        self.cap = pyshark.FileCapture(file)

    def get_letter(self, package_id, stream):
            if stream is None:
                data_limiter = 9
                packages = list()
            else:
                data_limiter = stream.data_limiter
                packages = stream.packages
            try:
                payload = str(self.cap[package_id - 1].http2.headers_path)
            except Retransmission:
                raise Retransmission
            letter_start_point = payload.find("search?q=") + data_limiter
            letter = payload[letter_start_point + len(packages): - (len(payload) - letter_start_point) + len(packages)+1]

            if letter == "%":
                try:
                    key_string = payload[letter_start_point + len(packages): - (len(payload) - letter_start_point) + len(packages) + 1 + 5]
                    if key_string in html_to_asci_dictionary:
                        stream.data_limiter += 5
                        return html_to_asci_dictionary[key_string]
                    else:
                        key_string = payload[letter_start_point + len(packages): - (len(payload) - letter_start_point) + len(packages) + 1 + 2]
                        if key_string in html_to_asci_dictionary:
                            stream.data_limiter += 2
                            return html_to_asci_dictionary[key_string]
                except:
                    print("Error occurred in methode get_letter in Class cap. Maybe Index out of bounds.")

            return letter
