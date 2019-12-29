

def is_new_stream(p_package, a_package, conf):
    def new_stream_for_android():
        start_package_ranges = conf.get_start_package_ranges()
        for ranges in start_package_ranges:
            if ranges[0] <= len(a_package) <= ranges[1]:
                return True
        else:
            return False

    def new_stream_for_desktop():
        start_package_ranges = conf.get_start_package_ranges()
        post_package_ranges = conf.get_post_package_ranges()
        if start_package_ranges[0] > len(p_package) >= start_package_ranges[1] and post_package_ranges[0] > len(a_package) > post_package_ranges[1] and len(p_package) > len(a_package):
            return True

    if conf.system == "mobile":
        return new_stream_for_android()
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


def is_second_package_of_stream(stream, a_package, conf):
    def is_second_package_of_stream_for_android():
        followed_package_ranges = conf.get_followed_package_ranges()
        for ranges in followed_package_ranges:
            if ranges[0] <= len(a_package) <= ranges[1]:
                return True
        else:
            return is_next_package(stream, a_package, conf)

    def is_second_package_of_stream_for_desktop():
        followed_package_ranges = conf.get_followed_package_ranges()
        if followed_package_ranges[0] > len(a_package) > followed_package_ranges[1]:
            return True

    if conf.system == "mobile":
        return is_second_package_of_stream_for_android()
    else:
        return is_second_package_of_stream_for_desktop()


def is_next_package(stream, a_package, conf):
    start_package_range = conf.get_start_package_ranges()[0]
    window_to_next_package = conf.get_window_to_next_package()
    followed_package_ranges = conf.get_followed_package_ranges()

    def is_next_package_for_android_special():
        for ranges in followed_package_ranges:
            if ranges[0] <= len(a_package) <= ranges[1]:
                return True
        else:
            if len(stream.packages) > 2 and len(stream.packages[-2]) + window_to_next_package >= len(a_package) >= len(stream.packages[-2]):
                return True
            elif start_package_range[0] + 15 >= len(a_package) >= start_package_range[0]:
                return True

    def is_next_package_for_android():
        for ranges in followed_package_ranges:
            if ranges[0] <= len(a_package) <= ranges[1]:
                return True
        else:
            if len(stream.packages[-1]) + window_to_next_package >= len(a_package) >= len(stream.packages[-1]):
                return True
            elif start_package_range[0] + 15 >= len(a_package) >= start_package_range[0]:
                return True

    def is_next_package_for_desktop():
        if len(stream.packages[-1]) + window_to_next_package >= len(a_package) >= len(stream.packages[-1]) or (len(stream.packages[-1]) - 1 <= len(a_package) <= len(stream.packages[-1])):
            return True

    if conf.system == "mobile":
        if len(stream.packages[-1]) >= 287:
            return is_next_package_for_android_special()
        else:
            return is_next_package_for_android()
    else:
        return is_next_package_for_desktop()
