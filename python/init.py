import logging

from yara_x import Scanner, Compiler, Rules
from scan import scan_ruleset_files


def init():
    my_rules_path = "../yara_rules"

    rules = compile_rules(my_rules_path)
    scanner = Scanner(rules)
    return scanner


def compile_rules(rules_path: str) -> Rules:
    try:
        yara_compiler = Compiler()
        rulesets = scan_ruleset_files(rules_path)
        yara_compiler.add_source(src=rulesets)
        rules = yara_compiler.build()
    except FileNotFoundError:
        # logging.error(f"Файл правил {rules_path} не найден. Скорее всего что-то пошло не так.")
        raise Exception(
            f"Файл правил {rules_path} не найден. Скорее всего что-то пошло не так.")

    return rules
