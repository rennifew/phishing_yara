import os

from yara_x import Scanner
from pathlib import Path

from python.helpers import print_matched_rules
from python.extract import *


def process_file(file_path: Path, scanner: Scanner):
    try:
        results = scanner.scan_file(file_path)
        print_matched_rules(results, file_path,
                            text='Найдено совпадение в файле:')
        
        if file_path.suffix == '.rtf':
            process_rtf_code(file_path, scanner)

        elif file_path.suffix in ['.dot', '.docm', '.docx', '.doc', '.dotm', '.xls', '.xlt', '.xlsb', '.xlsm', '.xltm', '.xlam', '.pptm', '.potm', '.ppsm', '.ppam', '.ppa', '.ppt']:
            process_vba_code(file_path, scanner)
            
        else:
            pass

    except Exception as e:
        print(f'Ошибка при сканировании {file_path}: {str(e)}')


def process_rtf_code(file_path: Path, scanner: Scanner):
    results_from_rtf = extract_from_rtf(file_path)
    if results_from_rtf:
        rtf_results = scanner.scan(results_from_rtf)
        print_matched_rules(rtf_results, file_path, tabs=1, text='Найдено совпадение внутри встреоенного OLE-файоа:')


def process_vba_code(file_path: Path, scanner: Scanner):
    vba_temp_path = extract_vba_macros_to_tempfile(str(file_path))

    if vba_temp_path:
        # Сканируем макросы
        iocs = extract_iocs_from_vba_file(vba_temp_path)
        vba_results = scanner.scan_file(str(vba_temp_path))
        os.remove(vba_temp_path)
        print_matched_rules(vba_results, file_path,
                            text='Обнаружены макросы в файле:', tabs=1, iocs=iocs)
