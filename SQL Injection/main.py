import pkg_resources
import subprocess
from robobrowser import RoboBrowser
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.chrome.options import Options

br = RoboBrowser()


def main(urls: list) -> None:
    installed = {pkg.key for pkg in pkg_resources.working_set}
    missing = {"sqlmap"} - installed

    if missing:
        execute("pip install sqlmap")

    for url in urls:
        br.open(url)
        form = br.get_form()
        if not form:
            break
        print(get_perf_log_on_load(url))
        br.submit_form(form)
        print(get_perf_log_on_load(url))

def get_perf_log_on_load(url, headless=True, filter=None):
    options = Options()
    options.add_experimental_option('w3c', False)
    options.headless = headless
    cap = DesiredCapabilities.CHROME
    cap["loggingPrefs"] = {"performance": "ALL"}
    # installed chromedriver.exe and identify path
    driver = webdriver.Chrome(r"C:\chromedriver.exe",
                              desired_capabilities=cap, options=options)
    # record and parse performance log
    driver.get(url)
    if filter:
        log = [item for item in driver.get_log("performance") if filter in str(item)]
    else:
        log = driver.get_log("performance")
    driver.close()

    return log


def execute(command):
    return subprocess.run(command, capture_output=True).stdout.decode()


if __name__ == "__main__":
    main(["https://accounts.google.com/signin/v2/identifier?service=youtube&uilel=3&passive=true&continue=https%3A%2F%2Fwww.youtube.com%2Fsignin%3Faction_handle_signin%3Dtrue%26app%3Ddesktop%26hl%3Den%26next%3Dhttps%253A%252F%252Fwww.youtube.com%252F&hl=en&ec=65620&flowName=GlifWebSignIn&flowEntry=ServiceLogin"])
