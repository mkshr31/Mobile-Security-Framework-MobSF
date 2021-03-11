# !/usr/bin/python
# coding=utf-8
import io
import logging
import os
import struct
import subprocess
import json

logger = logging.getLogger(__name__)

def getProcessOutput(cmd):
    process = subprocess.Popen(
        cmd,
        shell=False,
        stdout=subprocess.PIPE)
    process.wait()
    data, err = process.communicate()
    if process.returncode == 0:
        return data.decode('utf-8')
    else:
        logger.error(err)
    return ""

def check_elf_built(f):
    has_pi = False
    data = getProcessOutput(["/root/Mobile-Security-Framework-MobSF/StaticAnalyzer/tools/checksec", "--format=json", "--file=%s" % f])
    json_data = json.loads(data)
    pi_flag = json_data[f]["pie"]
    has_pi = (pi_flag == 'dso') or (pi_flag == 'yes')
    return has_pi

def res_analysis(app_dir):
    """Perform the elf analysis."""
    try:
        logger.info('Static Android Resource Analysis Started')
        elf_desc = {
            'html_infected':
                (
                    'Found html files infected by malware.',
                    'high',
                    'The built environment was probably'
                    ' infected by malware, The html file '
                    'used in this APK is infected.')}
        html_an_dic = {}
        for k in list(elf_desc.keys()):
            html_an_dic[k] = []
        resraw = os.path.join(app_dir, 'res', 'raw')
        assets = os.path.join(app_dir, 'assets')
        for resdir in (resraw, assets):
            if os.path.exists(resdir) and os.path.isdir(resdir):
                for pdir, _dirl, filel in os.walk(resdir):
                    for filename in filel:
                        if (filename.endswith('.htm')
                                or filename.endswith('.html')):
                            try:
                                filepath = os.path.join(pdir, filename)
                                buf = ''
                                with io.open(filepath, mode='rb') as filp:
                                    buf = filp.read()
                                if 'svchost.exe' in buf:
                                    html_an_dic['html_infected'].append(
                                        filepath.replace(app_dir, ''))
                            except Exception:
                                pass
        res = []
        for k, filelist in list(html_an_dic.items()):
            if len(filelist):
                descs = elf_desc.get(k)
                res.append({'title': descs[0],
                            'stat': descs[1],
                            'desc': descs[2],
                            'file': ' '.join(filelist),
                            })
        return res

    except Exception:
        logger.exception('Performing Resourse Analysis')


def elf_analysis(app_dir: str) -> list:
    """Perform the elf analysis."""
    try:
        logger.info('Static Android Binary Analysis Started')
        fgs = ['nopie', 'nonpie', 'no-pie']
        elf_desc = {
            'elf_no_pi':
                (
                    'Found elf built without Position Independent Executable'
                    ' (PIE) flag',
                    'high',
                    'In order to prevent an attacker from reliably jumping'
                    ' to, for example, a particular'
                    ' exploited function in memory, Address space layout'
                    ' randomization (ASLR) randomly '
                    'arranges the address space positions of key data areas'
                    ' of a process, including the '
                    'base of the executable and the positions of the stack,'
                    ' heap and libraries. Built with'
                    ' option <strong>-pie</strong>.')}
        elf_an_dic = {}
        for k in list(elf_desc.keys()):
            elf_an_dic[k] = []
        libdir = os.path.join(app_dir, 'lib')
        if os.path.exists(libdir):
            for pdir, _dirl, filel in os.walk(libdir):
                for fname in filel:
                    if fname.endswith('.so'):
                        try:
                            filepath = os.path.join(pdir, fname)
                            has_pie = check_elf_built(filepath)
                            if not has_pie:
                                if not any(pie_st in fgs for pie_st in fname):
                                    elf_an_dic['elf_no_pi'].append(
                                        filepath.replace(libdir, 'lib'))
                        except Exception:
                            pass
        res = []
        for k, filelist in list(elf_an_dic.items()):
            if len(filelist):
                descs = elf_desc.get(k)
                res.append({'title': descs[0],
                            'stat': descs[1],
                            'desc': descs[2],
                            'file': ' '.join(filelist),
                            })
        return res

    except Exception:
        logger.exception('Performing Binary Analysis')
