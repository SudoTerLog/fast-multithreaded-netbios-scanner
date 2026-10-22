# ===============================================================================
# БЛОК 1 - ИМПОРТ СИСТЕМНЫХ БИБЛИОТЕК PYTHON
# BLOCK 1 - IMPORTING PYTHON SYSTEM LIBRARIES
# ===============================================================================
import csv  # Модуль для удобной работы с таблицами формата CSV (чтение/запись) \ A module for convenient work with CSV-format tables (reading/writing)
import os  # Модуль для взаимодействия с операционной системой (определение типа ОС) \ Module for interacting with the operating system (detecting the OS type)
import socket  # Главный сетевой модуль для создания сокетов (вилок) и работы с портами \ The main network module for creating sockets and working with ports
import subprocess  # Модуль для скрытого запуска консольных утилит Windows (ping, nbtstat) \ A module for the hidden execution of Windows console utilities (ping, nbtstat)
from datetime import datetime  # Модуль для фиксации точной даты и времени проверки \ Module for recording the exact date and time of an inspection
import re  # Модуль регулярных выражений для поиска текста по сложным маскам \ Regular expression module for searching text using complex patterns
from concurrent.futures import ThreadPoolExecutor  # Мощный инструмент для многопоточного ускорения кода \ A powerful tool for multithreaded code acceleration
from pathlib import Path  # Современная библиотека для работы с системными путями к файлам \ A modern library for working with system file paths

# ===============================================================================
# БЛОК 2 - ГЛОБАЛЬНЫЕ НАСТРОЙКИ СКРИПТА
# BLOCK 2 - GLOBAL SCRIPT SETTINGS
# ===============================================================================
# Берем текущую системную дату и время в читаемом корпоративном формате
# We take the current system date and time in a readable corporate format.
current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Префикс рабочей локальной подсети 
# Local subnet prefix 
subnet = "192.168.1."

# Путь к файлу создается прямо в папке со скриптом
# The file path is created right inside the folder containing the script
csv_path = Path("network_report.csv")

# Задаем 50 параллельных потоков. Скрипт будет опрашивать 50 компьютеров одновременно
# We set up 50 parallel threads. The script will poll 50 computers simultaneously.
max_threads = 50 

# ===============================================================================
# БЛОК 3 - СИСТЕМНЫЕ ФУНКЦИИ ПРОВЕРКИ И РАЗВЕДКИ
# BLOCK 3 - SYSTEM FUNCTIONS FOR VERIFICATION AND RECONNAISSANCE
# ===============================================================================
def ping_ip(ip_address):
    """Быстрый пинг устройства для проверки, живое ли оно в сети."""
    # Если ОС Windows (nt), параметр пинга -n, если Linux/Mac — параметр -c
    # For Windows (NT) systems, the ping parameter is -n; for Linux/Mac, it is -c.
    param = "-n" if os.name == "nt" else "-c"
    # Задаем параметры ожидания ответа (тайм-аут) для разных операционных систем
    # Setting response wait parameters (timeouts) for different operating systems
    timeout_param = "-w" if os.name == "nt" else "-w"
    timeout_val = "200" if os.name == "nt" else "1"
    
    # Собираем пачку аргументов в единую системную команду для Windows
    # Assembling a collection of arguments into a single, cohesive command for Windows
    command = ["ping", param, "1", timeout_param, timeout_val, ip_address]
    try:
        # Запускаем пинг, перенаправляя весь текстовый мусор в DEVNULL (скрываем окно)
        # Run a ping, redirecting all the text clutter to DEVNULL (hiding the window)
        # Если код ответа равен 0 — узел успешно пингуется (вернули True)
        # If the response code is 0, the node is successfully pinged (returns True)
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except Exception:
        return False  # При любой ошибке считаем, что пинг не прошёл \ In the event of any error, we consider the ping to have failed.

def check_windows_ports(ip_address):
    """Проверка стандартных портов Windows (445, 135, 139) для обхода брандмауэра."""
    ports = [445, 135, 139]  # Список критических портов служб Windows (SMB, RPC) \ List of critical Windows service ports (SMB, RPC)
    for port in ports:
        # Создаем сетевой сокет типа TCP (STREAM) \ We create a network socket of type TCP (STREAM)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)  # Даем порту всего 100 миллисекунд на ответ (скоростной режим) \ We allow the port just 100 milliseconds to respond (high-speed mode)
        try:
            # Если метод connect_ex вернул 0 — порт открыт! Перед нами 100% Windows-машина
            # If the connect_ex method returned 0, the port is open! We are definitely dealing with a Windows machine.
            if s.connect_ex((ip_address, port)) == 0:
                return True
        except Exception:
            pass
        finally:
            s.close()  # В любом случае закрываем сокет, чтобы не забивать память ПК \ In any case, we close the socket so as not to clog up the PC's memory.
    return False  # Если ни один порт не отозвался, возвращаем ложь \ If no port responded, we return false.

def get_netbios_name(ip_address):
    """Высший пилотаж: отправка сырого UDP-пакета на порт 137 для кражи имени Windows-ПК."""
    # Заранее скомпилированный байтовый запрос протокола NetBIOS Name Service
    # Precompiled byte request for the NetBIOS Name Service protocol
    netbios_request = b'\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41' \
                      b'\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41' \
                      b'\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01'
    # Создаем UDP-сокет (DGRAM), так как NetBIOS работает без установки соединения
    # We create a UDP socket (DGRAM), since NetBIOS operates in a connectionless manner.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.15)  # Ограничение ожидания — 150 миллисекунд \ Wait limit — 150 milliseconds
    try:
        # Швыряем байтовый запрос прямо на 137 порт удаленного компьютера
        # We fire a byte-based request directly at port 137 of the remote computer.
        s.sendto(netbios_request, (ip_address, 137))
        # Ловим ответный пакет данных объемом до 1024 байт
        # We capture a response data packet of up to 1024 bytes.
        data, _ = s.recvfrom(1024)
        if len(data) > 57:
            # Вырезаем из байтового потока кусок с 57 по 72 байт — там лежит имя ПК
            # Extract the segment from byte 57 to byte 72 from the byte stream — that’s where the PC name is located.
            raw_name = data[57:72].split(b'\x00')[0].split(b' ')[0]
            # Декодируем байты в обычный читаемый текст, отбрасывая мусор
            # Decode the bytes into plain, readable text, discarding any junk.
            name = raw_name.decode('utf-8', errors='ignore').strip()
            # Если имя нашлось и это не служебный маркер Windows, отдаем его наружу
            # If a name is found and it is not a Windows system marker, we pass it out.
            if name and not name.startswith('IS~'): 
                return name
    except Exception:
        pass
    finally:
        s.close()  # Закрываем UDP-соединение \ Closing the UDP connection
    return None

def get_dns_name(ip_address):
    """Классический запрос буквенного Hostname через локальный DNS-кэш."""
    """A standard request for an alphabetic hostname via the local DNS cache."""
    try:
        # Делаем обратный DNS-запрос по IP-адресу
        # Perform a reverse DNS lookup for an IP address
        hostname, _, _, = socket.gethostbyaddr(ip_address)
        # Отрезаем доменную часть (берем текст до первой точки), чтобы получить короткое имя ПК
        # We strip off the domain part (taking the text before the first dot) to obtain the short computer name.
        return hostname.split('.')[0] 
    except socket.herror:
        return None  # Если DNS ничего не знает об этом адресе \ If DNS doesn't know anything about this address

def get_nbtstat_name(ip_address):
    """Запрос через родную утилиту Windows 'nbtstat -A' с разбором текста регулярками."""
    """A query via the native Windows utility 'nbtstat -A', with the text parsed using regular expressions."""
    if os.name != "nt":
        return None  # Если скрипт запущен не на Windows, утилита не сработает \ If the script is not run on Windows, the utility will not work.
    try:
        # Вызываем nbtstat и переводим ответ из кодировки DOS (cp866) в понятный текст
        # Invoke `nbtstat` and convert the response from the DOS encoding (CP866) into readable text.
        output = subprocess.check_output(f"nbtstat -A {ip_address}", shell=True, timeout=0.2).decode('cp866', errors='ignore')
        # Регулярка ищет в системной таблице строку, где написано <00> UNIQUE и забирает имя
        # The regular expression searches the system table for a row containing "<00> UNIQUE" and extracts the name.
        match = re.search(r"^\s+([A-Za-z0-9\-]+)\s+<00>\s+UNIQUE", output, re.MULTILINE)
        if match:
            return match.group(1).strip()  # Возвращаем очищенное имя из регулярного кармана (1) \ Returning the cleaned name from the regular expression capture group (1)
    except Exception:
        pass
    return None

def scan_host(ip):
    """Главный диспетчер проверки: склеивает все методы датчиков для одного IP."""
    is_alive = ping_ip(ip)  # Датчик 1: Проверяем обычный пинг \ Sensor 1: Checking a standard ping
    has_ports = check_windows_ports(ip)  # Датчик 2: Проверяем системные порты Windows \ Sensor 2: Checking Windows system ports
    
    # Если устройство молчит на пинг и порты заперты — оно выключено. Отдаем None 
    # If a device does not respond to a ping and its ports are closed, it is powered off. We return None.
    if not is_alive and not has_ports:
        return None
        
    # Берем то сетевое имя, которое получится добыть первым
    # We’ll take whichever network name we manage to obtain first.
    name = get_netbios_name(ip) or get_nbtstat_name(ip) or get_dns_name(ip)
    if not name:
        name = "Имя не определено"  # Заглушка, если железка жива, но шифруется \ A placeholder—used if the hardware is functional but encrypted.
        
    # Определяем статус: если открыты порты — это Windows, иначе — сетевой узел/смартфон
    # Determining status: if ports are open, it’s a Windows machine; otherwise, it’s a network node or smartphone.
    status = "Windows Device" if has_ports else "Живое устройство (Не Windows / Брандмауэр)"
    
    # Мгновенно выводим красивый живой лог работы в консоль
    # Instantly output a nicely formatted, live log of operations to the console
    print(f"[+] {current_time} Ответил: {ip} | {name} ({status})")
    
    # Возвращаем собранные данные в виде структурированного словаря
    # We return the collected data as a structured dictionary.
    return {"Date_Time": current_time, "IP": ip, "Status": status, "Device Name": name}

# ===============================================================================
# БЛОК 4 - ТОЧКА ВХОДА И МНОГОПОТОЧНЫЙ ДВИЖОК
# BLOCK 4 - ENTRY POINT AND MULTITHREADED ENGINE
# ===============================================================================
if __name__ == "__main__":
    print(f"Запуск сканирования подсети {subnet}0/24...")
    print(f"Используется потоков: {max_threads}. Сбор данных по Ping + DNS + NetBIOS + Ports...\n")
    
    # Быстро собираем генератором список всех IP подсети от 192.168.1.1 до 192.168.1.255
    # Using a generator, we quickly compile a list of all IP addresses in the subnet from 192.168.1.1 to 192.168.1.255
    ips_to_scan = [f"{subnet}{i}" for i in range(1, 255)]
    raw_report_data = []
    
    # Запускаем многопоточный движок ThreadPoolExecutor
    # Launching the multi-threaded ThreadPoolExecutor engine
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Функция .map раскидывает список IP-адресов по 50 параллельным потокам
        # The .map function distributes the list of IP addresses across 50 parallel threads.
        results = executor.map(scan_host, ips_to_scan)
        for res in results:
            raw_report_data.append(res)  # Накапливаем результаты в массив \ Accumulate results into an array
            
    # Bычищаем все пустые элементы None (выключенные ПК) из финального отчета
    # We remove all empty 'None' elements (powered-off PCs) from the final report.
    report_data = [item for item in raw_report_data if item is not None]
    
    # Умная сортировка: режем IP по точкам, берем последнюю цифру и превращаем в int
    # Smart sorting: split the IP address by dots, take the last number, and convert it to an int.
    # Благодаря этому адреса в таблице пойдут строго по порядку: .1, .2, .3 ... .255
    # Thanks to this, the addresses in the table will follow in strict order: .1, .2, .3 ... .255
    report_data.sort(key=lambda x: int(x["IP"].split(".")[-1]) if x and "IP" in x else 0)
    
    # ===============================================================================
    # БЛОК 5 - ЗАПИСИ В CSV ТАБЛИЦУ 
    # BLOCK 5 - WRITING TO A CSV TABLE
    # ===============================================================================
    try:
        # Автоматически создаем папки на Рабочем столе, если их еще не существовало
        # Automatically create folders on the desktop if they do not already exist
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Открываем файл в режиме добавления строк 'a' с кодировкой utf-8-sig для чтения в Excel
        #Open the file in append mode ('a') with 'utf-8-sig' encoding for reading in Excel.
        with open(csv_path, mode="a", newline="", encoding="utf-8-sig") as file_csv:
            # Разделитель ';', чтобы Excel автоматически разбил данные по красивым столбцам
            # Use the ';' separator so that Excel automatically splits the data into neat columns
            writer = csv.DictWriter(file_csv, fieldnames=["Date_Time", "IP", "Status", "Device Name"], delimiter=";")
            
            # Если файл создается впервые (его размер 0 байт), записываем шапку колонок
            # If the file is being created for the first time (its size is 0 bytes), we write the column headers.
            if csv_path.stat().st_size == 0:
                writer.writeheader()
                
            # Записываем всю пачку найденных устройств одной быстрой командой
            # We record the entire batch of discovered devices with a single quick command.
            writer.writerows(report_data)
            print(f"\n[+] Отчет успешно сохранен:\n{csv_path}")
    except Exception as e:
        # Если файл заблокирован (например, открыт в Excel), сработает этот блок защиты
        # If the file is locked (for example, if it is open in Excel), this protection block will be triggered.
        print(f"\n[-] Не удалось сохранить файл: {e}")