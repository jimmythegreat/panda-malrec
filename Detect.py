import subprocess
import pefile
import ConfigParser

paths = None

try:
    magic = __import__('magic')
except ImportError:
    magic = None


def set_paths(configuration_filename):
    global paths
    paths = {(None, None): 'start "%s"',
             ('dll', 32): '"%SystemRoot%\system32\rundll32.exe" "%s",DllMain',
             ('dll', 64): '"%SystemRoot%\SysWOW64\rundll32.exe" "%s",DllMain',
             ('exe', 32): 'start "%s"',
             ('exe', 64): 'start "%s"',
             ('sys', 32): 'sc create sample binPath=%s type=kernel & sc start sample',
             ('sys', 64): 'sc create sample binPath=%s type=kernel & sc start sample'}

    config = ConfigParser.ConfigParser()
    config.read(configuration_filename)

    if not config.has_section('Programs'):
        raise ConfigParser.MissingSectionHeaderError

    if config.has_option('Programs', 'pdf') and config.get('Programs', 'pdf'):
        paths[('pdf', None)] = '"%s"' % config.get('Programs', 'pdf').replace("%", "%%") + ' "%s"'

    if config.has_option('Programs', 'doc'):
        paths[('doc', None)] = '"%s"' % config.get('Programs', 'doc').replace("%", "%%") + ' "%s"'
    if config.has_option('Programs', 'xls'):
        paths[('xls', None)] = '"%s"' % config.get('Programs', 'xls').replace("%", "%%") + ' "%s"'
    if config.has_option('Programs', 'ppt'):
        paths[('ppt', None)] = '"%s"' % config.get('Programs', 'ppt').replace("%", "%%") + ' "%s"'

    if config.has_option('Programs', 'docx'):
        paths[('docx', None)] = '"%s"' % config.get('Programs', 'docx').replace("%", "%%") + ' "%s"'
    if config.has_option('Programs', 'xlsx'):
        paths[('xlsx', None)] = '"%s"' % config.get('Programs', 'xlsx').replace("%", "%%") + ' "%s"'
    if config.has_option('Programs', 'pptx'):
        paths[('pptx', None)] = '"%s"' % config.get('Programs', 'pptx').replace("%", "%%") + ' "%s"'

    if config.has_option('Programs', 'html'):
        paths[('html', None)] = '"%s"' % config.get('Programs', 'html').replace("%", "%%") + ' "%s"'

    if config.has_option('Programs', 'python'):
        paths[('py', None)] = '"%s"' % config.get('Programs', 'python').replace("%", "%%") + ' "%s"'


def get_file_type(host_filename):
    if magic:
        return magic.from_file(host_filename, mime=True)
    else:
        file_process = subprocess.Popen(['file', '--mime-type', '-b', host_filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = file_process.communicate()
        return output.strip()


def get_pefile_architecture(filename):
    pe = None
    architecture = 0
    try:
        # Check architecture of PE file
        pe = pefile.PE(filename, fast_load=True)
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            architecture = 64
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            architecture = 32
    except:
        pass
    if pe:
        pe.close()
    return architecture


def get_type(host_filename):
    pe = None
    try:
        pe = pefile.PE(host_filename, fast_load=True)
        if pe.OPTIONAL_HEADER.Subsystem == pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_NATIVE']:
            pe.close()
            return 'sys'
    except:
        pass
    if pe:
        pe.close()

    mime = get_file_type(host_filename).lower()

    if "dll" in mime or host_filename.endswith('dll'):
        return "dll"
    elif "pe32" in mime or "ms-dos" in mime or "dosexec" in mime or host_filename.endswith('exe'):
        return "exe"
    elif "pdf" in mime or mime.endswith('pdf'):
        return "pdf"
    elif "rich text format" in mime or "microsoft word" in mime or "microsoft office word" in mime or host_filename.endswith('doc'):
        return "doc"
    elif "msword" in mime or host_filename.endswith('docx'):
        return "docx"
    elif "microsoft office excel" in mime or "microsoft excel" in mime or host_filename.endswith('xls'):
        return "xls"
    elif "ms-excel" in mime or host_filename.endswith('xlsx'):
        return "xlsx"
    elif "microsoft powerpoint" in mime or host_filename.endswith('ppt'):
        return "ppt"
    elif "ms-powerpoint" in mime or host_filename.endswith('pptx'):
        return "pptx"
    elif "html" in mime or host_filename.endswith('html') or host_filename.endswith('htm'):
        return "html"
    # elif "zip" in mime or host_filename.endswith('zip'):
    #     return "zip"
    # elif "gzip" in mime:
    #     return "gzip"
    elif "python script" in mime or host_filename.endswith('py'):
        return "py"

    return None


def get_run_command(file_type, file_architecture, agent_filename):
    try:
        return paths[(file_type, file_architecture)] % agent_filename
    except KeyError:
        return None