

def is_new_stream(p_buffer, a_package, conf):
    start_package_ranges = conf.get_start_package_ranges()
    post_package_ranges = conf.get_post_package_ranges()

    def new_stream_for_ios():
        for ranges in start_package_ranges:
            if ranges[0] <= len(a_package) <= ranges[1]:
                return True
        return False

    def new_stream_for_android():
        # ob in den letzen 5 elementen des p_buffer die drei post packete enthalten sind
        if len(p_buffer) == p_buffer.size:
            p_length = [len(e.package) for e in p_buffer]

            find_start_package = False
            for ranges in start_package_ranges:
                # p_element ist das mittlerste Element des buffers
                if ranges[0] <= p_length[p_buffer.p_element] <= ranges[1]:
                    find_start_package = True

            if find_start_package is True:
                for j in range(0, p_buffer.p_element):
                    if post_package_ranges[0] <= p_length[j] <= post_package_ranges[1]:
                        return False
                for i in range(p_buffer.p_element + 1, len(p_length)):
                    if post_package_ranges[0] <= p_length[i] <= post_package_ranges[1]:
                        if i < len(p_length)-1:
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

    def new_stream_for_desktop():
        if start_package_ranges[0] >= len(p_buffer.get_last_as_package()) >= start_package_ranges[1] and post_package_ranges[0] >= len(a_package) >= post_package_ranges[1] and len(p_buffer.get_last_as_package()) > len(a_package):
            return True
        elif post_package_ranges == [0, 0]:
            if start_package_ranges[0] >= len(p_buffer.get_last_as_package()) >= start_package_ranges[1]:
                return True

    def new_stream_for_vpn():
        if start_package_ranges[0] > len(p_buffer.get_last_as_package()) >= start_package_ranges[1] and post_package_ranges[0] >= len(a_package) >= post_package_ranges[1]:
            return True

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
    def is_second_package_of_stream_for_android():
        followed_package_ranges = conf.get_followed_package_ranges()
        for ranges in followed_package_ranges:
            if ranges[0] <= len(a_package) <= ranges[1]:
                return True
        else:
            return is_next_package(stream, p_buffer, a_package, conf)

    def is_second_package_of_stream_for_desktop():
        followed_package_ranges = conf.get_followed_package_ranges()
        if followed_package_ranges[0] > len(a_package) > followed_package_ranges[1]:
            return True

    if conf.is_mobile():
        return is_second_package_of_stream_for_android()
    else:
        return is_second_package_of_stream_for_desktop()


def is_next_package(stream, p_buffer, a_package, conf):
    start_package_range = conf.get_start_package_ranges()[0]
    window_to_next_package = conf.get_window_to_next_package()
    followed_package_ranges = conf.get_followed_package_ranges()

    def is_next_package_for_android():
        for ranges in followed_package_ranges:
            if ranges[0] <= len(a_package) <= ranges[1]:
                return True
        else:
            if len(stream.packages[-1]) + window_to_next_package >= len(a_package) >= len(stream.packages[-1]):
                return True
            elif start_package_range[0] + 15 >= len(a_package) >= start_package_range[0] and len(a_package) > len(stream.packages[-1]):
                return True

    def is_next_package_for_desktop():
        if len(stream.packages[-1]) + window_to_next_package >= len(a_package) >= len(stream.packages[-1]) or (len(stream.packages[-1]) - window_to_next_package <= len(a_package) <= len(stream.packages[-1])):
            return True

    def is_next_package_for_vpn():
        if 180 >= len(p_buffer.get_last_as_package()) >= 110:
            if len(stream.packages[-1]) + window_to_next_package >= len(a_package) >= len(stream.packages[-1]) or (len(stream.packages[-1]) - window_to_next_package <= len(a_package) <= len(stream.packages[-1])):
                return True

    if conf.is_mobile():
        return is_next_package_for_android()
    elif conf.is_desktop():
        return is_next_package_for_desktop()
    elif conf.is_vpn():
        return is_next_package_for_vpn()
