from os import popen
from sys import argv

if len(argv) < 2:
    print("Использование:")
    print(f"  {argv[0]} <сеть или IP>")
    print()
    print("Примеры:")
    print(f"  {argv[0]} 192.168.1.0/24")
    print(f"  {argv[0]} 10.0.0.1")
    exit(1)

target = argv[-1]

print("=" * 60)
print(" Joyeuseo MongoDB Scanner (nmap)")
print("=" * 60)
print(f"Цель: {target}")
print("Порт: 27017")
print("Скрипт: mongodb-databases.nse")
print("=" * 60)
print()

cmd = "nmap --open --script=mongodb-databases.nse -p 27017 {0}".format(target)
print(f"Выполняется: {cmd}")
print()

result = popen(cmd).read()

reports = result.split("Nmap scan report for ")

found = []

for report in reports:
    if "| mongodb-databases:" in report:
        ip_line = report.split("\n")[0].strip()
        found.append(ip_line)

        print("-" * 60)
        print(f"НАЙДЕНО: {ip_line}")
        print("-" * 60)

        lines = report.split("\n")
        in_mongo_section = False
        for line in lines:
            if "| mongodb-databases:" in line:
                in_mongo_section = True
            if in_mongo_section:
                print(line)
                if line.strip() and not line.startswith("|") and not line.startswith("  "):
                    if not line.startswith("|_"):
                        in_mongo_section = False

print()
print("=" * 60)
print("РЕЗУЛЬТАТЫ")
print("=" * 60)

if found:
    print(f"Найдено MongoDB без аутентификации: {len(found)}")
    for f in found:
        print(f"  - {f}")
else:
    print("MongoDB без аутентификации не найдено.")
    print()
    print("Возможные причины:")
    print("  - MongoDB требует аутентификацию")
    print("  - Порт 27017 закрыт фильтром")
    print("  - Скрипт mongodb-databases.nse отсутствует")

print("=" * 60)