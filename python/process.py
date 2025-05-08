from yara_x import Scanner, ScanResults, Compiler, Rules
from pathlib import Path
import os
from olevba import VBA_Parser, VBA_Scanner
import tempfile

from helpers import print_matched_rules


def extract_vba_macros_to_tempfile(file_path: str) -> str | None:
    """
    Проверяет наличие VBA макросов в файле и, если есть, извлекает их в временный файл.
    Возвращает путь к временному файлу с макросами или None, если макросов нет.
    """
    vbaparser = VBA_Parser(file_path)
    try:
        if not vbaparser.detect_vba_macros():
            return None

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False, encoding='utf-8') as temp_file:
            for _, _, _, vba_code in vbaparser.extract_macros():
                temp_file.write(vba_code + '\n\n')
            return temp_file.name

    except Exception as e:
        print(f'Ошибка при экстракте vba макроса в файле{file_path}: {str(e)}')
    finally:
        vbaparser.close()


def extract_iocs_from_vba_file(vba_file_path: Path):
    with open(vba_file_path, 'r') as f:
        vba_scanner = VBA_Scanner(f.read())
        scan_results = vba_scanner.scan(include_decoded_strings=True)
        iocs = []
        for kw_type, keyword, description in scan_results:
            if kw_type == "IOC":
                iocs.append((keyword, description))
    return iocs


def process_file(file_path: Path, scanner: Scanner):
    try:
        results = scanner.scan_file(file_path)
        print_matched_rules(results, file_path,
                            text='Найдено совпадение в файле:')

        vba_temp_path = extract_vba_macros_to_tempfile(str(file_path))

        if vba_temp_path:
            # Сканируем макросы
            iocs = extract_iocs_from_vba_file(vba_temp_path)
            vba_results = scanner.scan_file(vba_temp_path)
            os.remove(vba_temp_path)
            print_matched_rules(vba_results, file_path,
                                text='Обнаружены макросы в файле:', tabs=1, iocs=iocs)

    except Exception as e:
        print(f'Ошибка при сканировании {file_path}: {str(e)}')
