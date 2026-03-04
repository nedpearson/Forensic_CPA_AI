from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

options = webdriver.ChromeOptions()
options.add_argument('--headless')
driver = webdriver.Chrome(options=options)
driver.get('http://localhost:3004')
time.sleep(2)
print('Console Logs Start:')
for entry in driver.get_log('browser'): print(entry)
print('Console Logs End')
