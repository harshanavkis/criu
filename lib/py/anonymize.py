# This file contains methods to anonymize criu images.

# In order to anonymize images three steps are followed:
#     - decode the binary image to json
#     - strip the necessary information from the json dict
#     - encode the json dict back to a binary image, which is now anonymized

# The following contents are being anonymized:
#     - Paths to files(unix files and regular files)
#     - All memory contents are just removed
#     - All process names

import hashlib
import os
import copy


def file_name_anon(file_list, ftype):
    levels = {}
    abs_ns_usk = []

    checksum = hashlib.sha1()

    for f in file_list:
        f_path = f
        if len(f) > 0 and f[0] == '@':
            abs_ns_usk.append(True)
            f_path = f_path[1:]
        else:
            abs_ns_usk.append(False)

        f_path = f_path.split('/')
        lev_num = 0

        for i, p in enumerate(f_path):
            if p == '':
                continue
            if lev_num not in levels:
                levels[lev_num] = {}
            if p not in levels[lev_num]:
                if i == 1:
                    levels[lev_num][p] = p
                else:
                    checksum.update(p)
                    levels[lev_num][p] = checksum.hexdigest()
            lev_num += 1

    for i, f in enumerate(file_list):
        f_path = f

        if f_path == '/':
            continue

        if len(f) > 0 and f[0] == '@':
            f_path = f[1:]

        f_path = f_path.split('/')
        lev_num = 0

        for j, p in enumerate(f_path):
            if p == '':
                continue
            f_path[j] = levels[lev_num][p]
            lev_num += 1
        f_path = '/'.join(f_path)

        if abs_ns_usk[i]:
            f_path = '@'+f_path

        file_list[i] = f_path

    return file_list


def files_anon(image):
    file_types = {}
    file_anons = {}
    type_names = {'REG': 'reg', 'UNIXSK': 'usk'}

    for e in image['entries']:
        if e['type'] in type_names:
            tname = type_names[e['type']]
            if tname not in file_types:
                file_types[tname] = []
            file_types[tname].append(e[tname]['name'])

    temp_file_types = copy.deepcopy(file_types)

    for ft in file_types:
        file_anons[ft] = file_name_anon(temp_file_types[ft], ft)
        file_anons[ft] = dict(zip(file_types[ft], file_anons[ft]))

    for i, e in enumerate(image['entries']):
        if e['type'] in type_names:
            tname = type_names[e['type']]
            fname = e[tname]['name']
            if e['type'] in type_names:
                image['entries'][i][tname]['name'] = file_anons[tname][fname]

    return image


def page_anon(image):
    page_num = image['entries'][0]['pages_id']
    page_file = 'pages-{}.img'.format(page_num)
    if os.stat(page_file).st_size > 0:
        page_size = os.stat(page_file).st_size
        image['entries'][0]['page_size'] = page_size
    else:
        print("Could not find page corresponding to page id:{}".format(
            page_num))

    return image


def core_anon(image):
    regs = image['entries'][0]['thread_info']['gpregs']

    for key in regs:
        if key != 'mode':
            regs[key] = 0
    image['entries'][0]['thread_info']['gpregs'] = regs

    proc_names = {}
    checksum = hashlib.sha1()
    tc = image['entries'][0]['tc']['comm']
    if tc not in proc_names:
        checksum.update(tc)
        proc_names[tc] = checksum.hexdigest()
    thread_core = image['entries'][0]['thread_core']['comm']
    if thread_core not in proc_names:
        checksum.update(thread_core)
        proc_names[thread_core] = checksum.hexdigest()

    image['entries'][0]['tc']['comm'] = proc_names[tc]
    image['entries'][0]['thread_core']['comm'] = proc_names[thread_core]

    return image


anonymizers = {
    'FILES': files_anon,
    'PAGEMAP': page_anon,
    'CORE': core_anon
}


def anon_handler(image):
    magic = image['magic']

    if magic not in anonymizers:
        return -1

    handler = anonymizers[magic]
    anon_img = handler(image)

    return anon_img
