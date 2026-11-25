"""Review a saved text HTTP response and render a Markdown report."""

import argparse
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

STATUS_LINE = re.compile(r"HTTP/\d+(?:\.\d+)? ([1-5]\d{2})(?:[ \t].*)?")
FIELD_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
SAFE_REFERRER_POLICIES = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}


@dataclass(frozen=True)
class Check:
    name: str
    accepts: Callable[[str], bool]
    recommendation: str
    passing_status: str = "Пройдено"


def parse_response(raw: str) -> tuple[int, dict[str, list[str]]]:
    """Read one response head and ignore the body after the blank line."""
    head, separator, _ = raw.partition("\n\n")
    # A header-only text export may end with a single newline.
    lines = (head if separator else raw.rstrip("\n")).split("\n")
    status = STATUS_LINE.fullmatch(lines[0])
    if status is None:
        raise ValueError("Первая строка должна иметь вид HTTP/1.1 200 OK.")

    headers: dict[str, list[str]] = {}
    for line_number, line in enumerate(lines[1:], start=2):
        name, colon, value = line.partition(":")
        if not colon or not FIELD_NAME.fullmatch(name):
            raise ValueError(f"Некорректный заголовок в строке {line_number}.")
        headers.setdefault(name.lower(), []).append(value.strip(" \t"))
    return int(status[1]), headers


def positive_max_age(value: str) -> bool:
    directives = [part.strip(" \t") for part in value.split(";")]
    max_age = [part for part in directives if part.partition("=")[0].strip().lower() == "max-age"]
    if len(max_age) != 1:
        return False
    match = re.fullmatch(r'max-age[ \t]*=[ \t]*(?:"([0-9]+)"|([0-9]+))', max_age[0], re.I)
    return bool(match and (match[1] or match[2]).lstrip("0"))


CHECKS = (
    Check("Strict-Transport-Security", positive_max_age,
          "Для HTTPS проверьте настройку HSTS и положительное значение max-age."),
    Check("X-Content-Type-Options", lambda value: value.lower() == "nosniff",
          "Укажите nosniff и проверьте корректность Content-Type."),
    Check("Referrer-Policy", SAFE_REFERRER_POLICIES.__contains__,
          "Сверьте политику с задачами приложения. Пример базового значения — strict-origin-when-cross-origin."),
    Check("Content-Security-Policy", bool,
          "Для HTML проверьте применимость CSP и подберите директивы под источники страницы.",
          "Заголовок присутствует"),
)


def evaluate(check: Check, values: list[str]) -> tuple[str, str]:
    if not values:
        return "Отсутствует", check.recommendation
    if len(values) > 1:
        return "Ручная проверка", "Повторяющиеся строки требуют проверки по правилам этого заголовка."
    if check.name == "Referrer-Policy" and "," in values[0]:
        return "Ручная проверка", "Проверьте последовательность значений и поддержку браузерами."
    if not check.accepts(values[0]):
        return "Требует проверки", check.recommendation
    if check.name == "Content-Security-Policy":
        return check.passing_status, "Проверьте директивы вручную с учётом ресурсов страницы."
    return check.passing_status, "Соответствует правилу инструмента."


def render_report(status: int, headers: dict[str, list[str]], scheme: str) -> str:
    lines = [
        "# Проверка HTTP-заголовков",
        "",
        f"Схема запроса — **{scheme.upper()}**. Код ответа — **{status}**.",
        "",
        "Результаты относятся к одному сохранённому ответу. Для выводов о приложении нужен контекст страницы.",
        "",
        "| Заголовок | Результат | Комментарий |",
        "| --- | --- | --- |",
    ]
    for check in CHECKS:
        if check.name == "Strict-Transport-Security" and scheme == "http":
            result, note = "Не применимо", "Браузер учитывает HSTS только при получении по HTTPS."
        else:
            result, note = evaluate(check, headers.get(check.name.lower(), []))
        lines.append(f"| `{check.name}` | {result} | {note} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Офлайн-проверка сохранённых HTTP-заголовков.")
    parser.add_argument("response", type=Path, help="Текстовый файл с одним HTTP-ответом")
    parser.add_argument("--scheme", choices=("http", "https"), required=True,
                        help="Схема исходного запроса")
    parser.add_argument("--output", type=Path, required=True, help="Новый Markdown-файл для отчёта")
    args = parser.parse_args()
    try:
        status, headers = parse_response(args.response.read_text(encoding="utf-8-sig"))
        report = render_report(status, headers, args.scheme)
        with args.output.open("x", encoding="utf-8") as output:
            output.write(report)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Ошибка: {error}\n")

    print(f"Отчёт записан: {args.output}")


if __name__ == "__main__":
    main()
