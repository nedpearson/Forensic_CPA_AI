from selenium import webdriver
import time

options = webdriver.ChromeOptions()
options.add_argument('--headless')
driver = webdriver.Chrome(options=options)
driver.get('http://localhost:3004')
time.sleep(2)
print('Console Logs Start:')
for entry in driver.get_log('browser'): print(entry)
print('Console Logs End')
