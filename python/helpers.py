from argparse import ArgumentTypeError
import re
from typing import List
from yara_x import ScanResults
from pathlib import Path


def endless_input(title, *options):
    print(title)
    for i, option in enumerate(options):
        print(f'{i+1}. {option}')
    while True:
        try:
            choice = int(input('Номер: ')) - 1
            if 0 <= choice < len(options):
                return options[choice]
        except ValueError:
            pass
        print('Invalid option. Please try again.')


def print_matched_rules(results: ScanResults, file_path: Path, text: str, tabs:int = 0, iocs=None):
    if results and results.matching_rules:
        print(f"\n{'\t'*tabs}{text} {file_path.resolve()}")
        print(f"{'\t'*tabs}🔍 Сработавшие правила:")
        for rule in results.matching_rules:
            print(f"{'\t'*tabs}💹 {rule.identifier} - {rule.metadata[0][1]}")

        if iocs:
            print(f"\n{'\t'*tabs}IOC's:")
            for keyword, description in iocs:
                print(f"{'\t'*tabs}-: {keyword} ({description})")
    else:
        print('\n'+f'Совпадений в файле {file_path.resolve()} не ОБНАРУЖЕНО')



def sanitize_foldername(name: str) -> str:
    illegal_chars = r'[/\\|\[\]\{\}:<>+=;,?!*"~#$%&@\']'
    return re.sub(illegal_chars, '_', name)

def save_attachment(file: Path, payload: bytes) -> None:
    with file.open('wb') as f:
        print(f'>> Сохраняем вложение в "{file}"')
        f.write(payload)

def get_eml_files_from(path: Path, recursively: bool = False) -> List[Path]:
    if recursively:
        return list(path.rglob('*.eml'))
    return list(path.glob('*.eml'))

def check_file(arg_value: str) -> Path:
    file = Path(arg_value)
    if file.is_file() and file.suffix == '.eml':
        return file
    raise ArgumentTypeError(f'"{file}" не является EML файлов')

def check_path(arg_value: str) -> Path:
    path = Path(arg_value)
    if path.is_dir():
        return path
    raise ArgumentTypeError(f'"{path}" Не является валидной директорией')