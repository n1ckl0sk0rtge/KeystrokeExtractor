
def is_new_stream(p_buffer, a_package, conf):
    """
    this function is called to check if the currently selected a_package
    is the start package of a keystroke stream

    :param p_buffer: instance of class PackageBuffer which contains the last PackageBuffer.size packages of
    the network stream
    :param a_package: the currently selected package, for that this function will
    check if it is the begin of a new sequence
    :param conf: providing the configuration to this function
    :return: returns a true if this package is teh begin of a new stream and false if not
    """

    # get the ranges for start and post package from config
    start_package_ranges = conf.get_start_package_ranges()
    post_package_ranges = conf.get_post_package_ranges()

    # nested function, which is called if the system is set to "ios" in the config
    def new_stream_for_ios():
        # iterate over all possible/provides ranges from config
        for ranges in start_package_ranges:
            if ranges[0] <= len(a_package) <= ranges[1]:
                # return true if the package size is within the range
                return True
        return False

    # nested function, which is called if the system is set to "android" in the config
    def new_stream_for_android():
        # check if the buffer is filled
        if len(p_buffer) == p_buffer.size:
            # define a list which contains the different length of each package from the buffer
            p_length = [len(e.package) for e in p_buffer]

            find_start_package = False
            # iterate over all possible/provides ranges from config
            for ranges in start_package_ranges:
                # checks if the package in the middle of teh buffer fulfill the requirements for a start package
                if ranges[0] <= p_length[p_buffer.p_element] <= ranges[1]:
                    find_start_package = True

            # if the package in the middle of teh buffer fulfill the requirements for a start package
            if find_start_package is True:
                # iterate over the packages in front of the middle package from the buffer
                for j in range(0, p_buffer.p_element):
                    # if the size of those packages are within the range that is defined in the conf for post_package
                    if post_package_ranges[0] <= p_length[j] <= post_package_ranges[1]:
                        return False
                # iterate over the packages at the end of the middle package from the buffer
                for i in range(p_buffer.p_element + 1, len(p_length)):
                    # if the size of those packages are within the range that is defined in the conf for post_package
                    if post_package_ranges[0] <= p_length[i] <= post_package_ranges[1]:
                        # if the selected package at pos i not the the last one from the buffer
                        if i < len(p_buffer)-1:
                            # check if the next package is bigger in size then the current selected one
                            if p_length[i+1] >= p_length[i]:
                                continue
                            else:
                                return False
                        else:
                            continue
                    else:
                        return False
                return True
            else:
                return False
        else:
            return False

    # nested function, which is called if the system is set to "desktop" in the config
    def new_stream_for_desktop():
        # checks if the last package of the buffer which is the predecessor of the currently selected one fulfill
        # the requirements for a start package and
        # if the current selected package is in range for being a post-package and
        # if the predecessor is bigger then the successor
        if start_package_ranges[0] >= len(p_buffer.get_last_as_package()) >= start_package_ranges[1] and \
                post_package_ranges[0] >= len(a_package) >= post_package_ranges[1] and \
                len(p_buffer.get_last_as_package()) > len(a_package):
            return True

    # nested function, which is called if the system is set to "vpn" in the config
    def new_stream_for_vpn():
        # checks if the last package of the buffer which is the predecessor of the currently selected one fulfill
        # the requirements for a start package and
        # if the current selected package is in range for being a post-package
        if start_package_ranges[0] > len(p_buffer.get_last_as_package()) >= start_package_ranges[1] and \
                post_package_ranges[0] >= len(a_package) >= post_package_ranges[1]:
            return True

    # check the configuration and call the corresponding function
    if conf.is_android():
        return new_stream_for_android()
    elif conf.is_ios():
        return new_stream_for_ios()
    elif conf.is_vpn():
        return new_stream_for_vpn()
    else:
        return new_stream_for_desktop()


def is_stream_from_new_source(keystroke_stream, p_package):
    for streams in keystroke_stream:
        try:
            ip_version = streams.ip_version_check()
            if streams.source_ip == p_package[ip_version].src:
                return False
        except:
            pass
    return True


def is_second_package_of_stream(stream, p_buffer, a_package, conf):
    """
    this function is called to check if the currently selected a_package
    is the second package of a keystroke stream

    :param stream: the current keystroke stream (instance of class Stream) for which this function checks if the
    selected package fulfils the requirements of being the second package of the stream
    :param p_buffer: instance of class PackageBuffer which contains the last PackageBuffer.size packages of
    the network stream
    :param a_package: the currently selected package, for that this function will
    check if it is the begin of a new sequence
    :param conf: providing the configuration to this function
    :return: returns a true if this package is teh begin of a new stream and false if not
    """
    # get the ranges for the second package from config
    followed_package_ranges = conf.get_followed_package_ranges()

    # nested function, which is called if the system is set to "android" in the config
    def is_second_package_of_stream_for_android():
        # iterate over all possible/provides ranges from config
        for ranges in followed_package_ranges:
            if ranges[0] <= len(a_package) <= ranges[1]:
                # return true if the package size is within the range
                return True
        else:
            # if this package does not fulfil the requirements to a specific type of second packages it can still be
            # the second package of the given stream by fulfilling the requirements for a the "next packages"
            return is_next_package(stream, p_buffer, a_package, conf)

    # nested function, which is called if the system is set to "desktop" in the config
    def is_second_package_of_stream_for_desktop():
        # iterate over all possible/provides ranges from config
        if followed_package_ranges[0] > len(a_package) > followed_package_ranges[1]:
            return True

    # check the configuration and call the corresponding function
    if conf.is_mobile():
        return is_second_package_of_stream_for_android()
    else:
        return is_second_package_of_stream_for_desktop()


def is_next_package(stream, p_buffer, a_package, conf):
    """
    this function is called to check if the currently selected a_package
    is part of a keystroke stream

    :param stream: the current keystroke stream (instance of class Stream) for which this function checks if the
    selected package fulfils the requirements of being the second package of the stream
    :param p_buffer: instance of class PackageBuffer which contains the last PackageBuffer.size packages of
    the network stream
    :param a_package: the currently selected package, for that this function will
    check if it is the begin of a new sequence
    :param conf: providing the configuration to this function
    :return: returns a true if this package is teh begin of a new stream and false if not
    """
    # get the ranges from config
    start_package_range = conf.get_start_package_ranges()[0]
    window_to_next_package = conf.get_window_to_next_package()
    followed_package_ranges = conf.get_followed_package_ranges()

    # nested function, which is called if the system is set to "android" or "ios" in the config
    def is_next_package_for_mobile():
        # iterate over all possible/provides ranges from config
        for ranges in followed_package_ranges:
            if ranges[0] <= len(a_package) <= ranges[1]:
                return True
        else:
            # if size of a_package is not in the given ranges for followed package
            # check, if the package is smaller then the size of the previous package + window_to_next_package from the
            # keystroke stream, but bigger then it's actual size
            if len(stream.packages[-1]) + window_to_next_package >= len(a_package) >= len(stream.packages[-1]):
                return True
            # check, if package is smaller then the size of the allowed size of a start package
            # + window_to_next_package, but bigger then the size of the last package of the given keystroke stream
            elif start_package_range[0] + window_to_next_package >= len(a_package) >= start_package_range[0] and \
                    len(a_package) > len(stream.packages[-1]):
                return True

    # nested function, which is called if the system is set to "desktop" or "ios" in the config
    def is_next_package_for_desktop():
        # check, if the size of the current package is between the size of the
        # previous package +/- window_to_next_package
        if len(stream.packages[-1]) + window_to_next_package >= len(a_package) >= len(stream.packages[-1]) or \
                (len(stream.packages[-1]) - window_to_next_package <= len(a_package) <= len(stream.packages[-1])):
            return True

    # check the configuration and call the corresponding function
    if conf.is_mobile():
        return is_next_package_for_mobile()
    elif conf.is_desktop() or conf.is_vpn():
        return is_next_package_for_desktop()
