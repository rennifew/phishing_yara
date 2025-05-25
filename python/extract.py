import tempfile
from pathlib import Path

from python.tools.olevba import VBA_Parser, VBA_Scanner
from python.tools.rtfobj import RtfObjParser



def extract_vba_macros_to_tempfile(file_path: str) -> str | None:
    vbaparser = VBA_Parser(file_path)
    try:
        if not vbaparser.detect_vba_macros():
            return None   

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False, dir='.',encoding='utf-8') as temp_file:
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

def extract_iocs_from_vba_file(vba_file_path: str) -> list:
    iocs = []
    with open(file=vba_file_path, mode='r', encoding='utf-8') as f:
        vba_scanner = VBA_Scanner(f.read())
        scan_results = vba_scanner.scan(include_decoded_strings=True)
        for kw_type, keyword, description in scan_results:
            if kw_type == "IOC":
                iocs.append((keyword, description))
    return iocs