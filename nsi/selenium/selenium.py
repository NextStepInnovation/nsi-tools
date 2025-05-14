import typing as T
from pathlib import Path
import base64

import selenium
from selenium.webdriver import Chrome
from selenium.webdriver.chrome.options import ChromiumOptions
from selenium.webdriver.common.by import By

from .. import logging
from ..toolz import *

log = logging.new_log(__name__)

def headless_driver():
    options = ChromiumOptions()
    pipe(
        ['--headless=new', '--no-sandbox'],
        map(options.add_argument),
        tuple,
    )
    
    return selenium.webdriver.Chrome(options=options)

def click_button_by_text(driver, text: str):
    driver.find_element(
        By.XPATH, f"//button[contains(text(), '{text}')]"
    ).click()
    return True


@curry
def print_pdf(driver: Chrome, url_or_file: str | Path, output: Path = None, 
              prep_func: T.Callable[[Chrome, str | Path], bool] = None, 
              as_data: bool = False):

    url = str(url_or_file)
    if not url.startswith('http'):
        path = Path(url_or_file)
        url = f"file://{path.resolve()}"

        if output is None:
            output_path = path.parent / f'{path.stem}.pdf'
        else:
            output_path = Path(output)
    else:
        if output is None:
            output_path = f'output-{mdf(url)}.pdf'
        else:
            output_path = Path(output)

    driver.get(url)
    if prep_func and not prep_func(driver, url_or_file):
        log.error(
            'Prep function failed'
        )

    print_settings = {
        "recentDestinations": [{
            "id": "Save as PDF",
            "origin": "local",
            "account": "",
        }],
        "selectedDestinationId": "Save as PDF",
        "version": 2,
        "isHeaderFooterEnabled": False,
        "isLandscapeEnabled": True
    }
    pdf_data = driver.execute_cdp_cmd("Page.printToPDF", print_settings)
    if as_data:
        return base64.b64decode(pdf_data['data'])
    with output_path.open('wb') as wfp:
        wfp.write(base64.b64decode(pdf_data['data']))
