
from pathlib import Path
from python.helpers import endless_input
from python.init import init
from python.scan import scan_directory

if __name__ == '__main__':
    malware_relative_path = "./malware/"
    malware_abs_path = Path(malware_relative_path).resolve()

    scanner = init()

    file_type = endless_input('Выберите тип файлов для сканирования:', 'ppt', 'pdf', 'rtf', 'vba', 'doc','eml', 'lnk')
    malware_dir_path = Path(f"{malware_abs_path}/{file_type}")

    scan_directory(malware_dir_path, scanner=scanner)
