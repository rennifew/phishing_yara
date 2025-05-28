import tempfile

from email import policy, message_from_file

from pathlib import Path
from python.helpers import sanitize_foldername, save_attachment
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


def extract_attachments(eml_filepath: Path) -> list:
    destination = Path('./malware/attachments/')
    attachments_paths = []
    with eml_filepath.open() as f:
        email_message = message_from_file(f, policy=policy.default)

        # ignore inline attachments
        attachments = [item for item in email_message.iter_attachments() if item.is_attachment()]  # type: ignore

        if not attachments:
            print('>> В письме не обнаружено вложений!')
            return []
        
        for attachment in attachments:
            filename = attachment.get_filename()
            print(f'>> Обнаружено вложение: {filename}')
            filepath = destination / filename
            payload = attachment.get_payload(decode=True)
            if filepath.exists():
                overwrite = input(f'>> Файл с именем "{filename}" уже существует! Перезаписать? (Y/n)? ')
                save_attachment(filepath, payload) if overwrite.upper() == 'Y' else print('>> Пропускаем файл...') 
            else:
                save_attachment(filepath, payload)

        attachments_paths.append(filepath)
    return attachments_paths


