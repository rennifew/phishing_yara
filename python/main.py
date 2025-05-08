
from helpers import endless_input
from pathlib import Path
from init import init
from scan import scan_directory

if __name__ == '__main__':
    malware_path = "../malware/"

    scanner = init()

    file_type = endless_input('Выберите тип файлов для сканирования:', 'vba', 'doc','eml','lnk')
    malware_dir_path = Path(f"{malware_path}/{file_type}")

    scan_directory(malware_dir_path, scanner=scanner)
