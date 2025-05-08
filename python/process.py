from io import BytesIO
from yara_x import Scanner, ScanResults, Compiler, Rules
from pathlib import Path
import os
import tempfile
from python.olevba import VBA_Parser, VBA_Scanner, FileOpenError
from python.rtfobj import rtf_iter_objects, RtfObjParser, is_rtf
from python.helpers import print_matched_rules


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


def extract_from_rtf(file_path: Path):
    with open(file_path, 'rb') as f:
        rtfp = RtfObjParser(f.read())
        rtfp.parse()
        for rtfobj in rtfp.objects:
            if rtfobj.is_ole:
                if rtfobj.oledata_size is None:
                    return None
                else:
                    return rtfobj.oledata

def extract_iocs_from_vba_file(vba_file_path: Path):
    with open(vba_file_path, 'r', encoding='utf-8') as f:
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
        if file_path.suffix == '.rtf':
            process_rtf_code(file_path, scanner)
        else:
            process_vba_code(file_path, scanner)
    except Exception as e:
        print(f'Ошибка при сканировании {file_path}: {str(e)}')

def process_rtf_code(file_path: Path, scanner: Scanner):
    results_from_rtf = extract_from_rtf(file_path)
    if results_from_rtf:
        rtf_results = scanner.scan(results_from_rtf)
        print_matched_rules(rtf_results, file_path, tabs=1, text='Найдено совпадение внутри макроса RTF-файла:')
    else:
        print('\n\t'+f'Совпадений в макросах в файле {file_path.resolve()} не ОБНАРУЖЕНО')

def process_vba_code(file_path: Path, scanner: Scanner):
    vba_temp_path = extract_vba_macros_to_tempfile(str(file_path))

    if vba_temp_path:
        # Сканируем макросы
        iocs = extract_iocs_from_vba_file(vba_temp_path)
        vba_results = scanner.scan_file(vba_temp_path)
        os.remove(vba_temp_path)
        print_matched_rules(vba_results, file_path,
                            text='Обнаружены макросы в файле:', tabs=1, iocs=iocs)