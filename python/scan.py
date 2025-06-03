from pathlib import Path
import os
from python.process import process_file, rules_matched_count
from python.helpers import print_results
import time



def scan_directory(malware_dir: Path, scanner):
    """
    Обходит директорию и сканирует все файлы.
    """
    print(f"Запуск сканирования директории {malware_dir.resolve()}")
    start = time.time()
    counter = 0
    for file in malware_dir.glob('**/*'):
        if file.is_file():
            counter += 1
            process_file(file, scanner)
    end = time.time()
    print_results(all_files_count=counter, rules_count=rules_matched_count[0], elapsed_time=(end-start))

def scan_ruleset_files(rule_dir) -> str:
    all_content = ""
    for dirpath, dirnames, filenames in os.walk(rule_dir):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    all_content += file.read() + "\n"
            except Exception as e:
                print(f"Ошибка при чтении файла {file_path}: {e}")
    if all_content == "":
        raise Exception("Правила пустые, скорее всего, что-то пошло не так!")
    else:
        return all_content


