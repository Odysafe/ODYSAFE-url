"""Regenerate the browser catalog after editing locales/en.json.

Run with: python -m app.web.build_i18n
French strings are stable keys. Language never changes stored values or routes.
"""
import hashlib
import json
from pathlib import Path


def main():
    root = Path(__file__).parent
    catalog = json.loads((root / 'locales/en.json').read_text(encoding='utf-8'))
    keys = {hashlib.sha256(source.encode()).hexdigest()[:16]: source for source in catalog}
    (root / 'static/i18n-catalog.js').write_text(
        'window.ODYSAFE_TRANSLATIONS=' + json.dumps(catalog, ensure_ascii=False) + ';\n'
        'window.ODYSAFE_TRANSLATION_KEYS=' + json.dumps(keys, ensure_ascii=False) + ';\n',
        encoding='utf-8')


if __name__ == '__main__':
    main()
