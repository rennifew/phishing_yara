# Противодействие фишинговым атакам путем распознавания вредоносных вложений в электронных документах

Данный репозиторий содержит разработку и инструменты для дипломной работы, посвящённой методам борьбы с фишинговыми атаками через анализ и распознавание вредоносных вложений в электронных документах с использованием детектирующих правил YARA.

---

## Описание проекта

В рамках работы реализован комплексный подход к выявлению вредоносного кода и подозрительных объектов в документах, которые могут использоваться злоумышленниками для фишинговых атак. Основная идея - автоматизированное сканирование вложений с помощью правил YARA, позволяющих эффективно обнаруживать известные и потенциально опасные шаблоны.

---

## Структура репозитория

- **python/** - скрипты на Python для запуска сканирования, обработки результатов и интеграции с YARA.
- **yara_rules/** - набор правил YARA, описывающих сигнатуры вредоносных вложений и фишинговых шаблонов.
  
---

## Основные возможности

- **Сканирование вложений** - автоматический анализ файлов и извлечение макросов, скриптов и других потенциально опасных компонентов.
- **Использование YARA** - применение гибких и расширяемых правил для обнаружения вредоносных шаблонов.
- **Отчётность** - вывод подробной информации о сработавших правилах и найденных индикаторах компрометации (IOC).
- **Поддержка различных форматов** - работа с популярными форматами электронных документов, включая офисные файлы с макросами.

---
## Используемые технологии

- **Python** - основной язык разработки скриптов и логики обработки.
- **[YARA_X](https://virustotal.github.io/yara-x/docs/api/python/)** - Python пакет для создания и применения правил обнаружения вредоносного кода.
- **[olevba](https://github.com/decalage2/oletools/wiki/olevba)** для извлечения макросов из офисных документов.


---

## Пример использования

```
PS D:\yara\phishing-yara> python main.py
Выберите тип файлов для сканирования:
1. vba
2. doc
3. eml
4. lnk
Номер: 2
Запуск сканирования директории D:\yara\phishing-yara\malware\doc

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\0b41ad678426a4712683dc4f7693b3b94554b5f9b68beef945b6b699b61822a7.xlsm
🔍 Сработавшие правила:
💹 Contains_VBA_macro_code - Обнаружение MS Office документа с встроенным VBA макросом

        Обнаружены макросы в файле: D:\yara\phishing-yara\malware\doc\0b41ad678426a4712683dc4f7693b3b94554b5f9b68beef945b6b699b61822a7.xlsm
        🔍 Сработавшие правила:
        💹 VBA_Open_File - Обнаружение процесса открытия какого файла в коде макроса
        💹 VBA_May_run_an_executable_file_or_a_system_command - Обнаружение запуска исполняемых файлов или системных команд в коде макроса
        💹 VBA_May_Create_OLE_Object - Обнаружение создания OLE-объекта
        💹 VBA_May_Enumerate_Windows - Обнаружение перебора окон приложения

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\25a3bb04c005e532243ec54e2f15448e8c96ba5ac666ca4714d7cb970a76f9a3.xlsm
🔍 Сработавшие правила:
💹 Contains_VBA_macro_code - Обнаружение MS Office документа с встроенным VBA макросом

        Обнаружены макросы в файле: D:\yara\phishing-yara\malware\doc\25a3bb04c005e532243ec54e2f15448e8c96ba5ac666ca4714d7cb970a76f9a3.xlsm
        🔍 Сработавшие правила:
        💹 VBA_Open_File - Обнаружение процесса открытия какого файла в коде макроса
        💹 VBA_May_Write_to_file - Обнаружение процесса записи чего-либо в файл в коде макроса
        💹 VBA_May_Run_PowerShell_Commands - Обнаружение запуска PowerShell-команд из макроса
        💹 VBA_May_Call_DLL_Using_XLM_XLF - Обнаружение вызова DLL через Excel 4 Macros (XLM/XLF)
        💹 VBA_May_Obfuscate_Strings - Обнаружение попытки обфускации строк

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\2736e27dd5936144379b4da3b8415359695926d46ba6af0e79b7ea8e5dc6f277.xlsx
🔍 Сработавшие правила:
💹 VBA_May_Call_DLL_Using_XLM_XLF - Обнаружение вызова DLL через Excel 4 Macros (XLM/XLF)
💹 VBA_May_Obfuscate_Strings - Обнаружение попытки обфускации строк

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\432557a5f88577dc0043c1aa1a28ce07ce3f566083eada337648293b0cff5ce6.xlsm
🔍 Сработавшие правила:
💹 Contains_VBA_macro_code - Обнаружение MS Office документа с встроенным VBA макросом
💹 VBA_May_Run_Code_From_DLL - Обнаружение вызова кода из DLL

        Обнаружены макросы в файле: D:\yara\phishing-yara\malware\doc\432557a5f88577dc0043c1aa1a28ce07ce3f566083eada337648293b0cff5ce6.xlsm
        🔍 Сработавшие правила:
        💹 VBA_Open_File - Обнаружение процесса открытия какого файла в коде макроса
        💹 VBA_May_Write_to_file - Обнаружение процесса записи чего-либо в файл в коде макроса
        💹 VBA_May_Read_Or_Write_Binary_File - Обнаружение процесса чтения или записи бинарного файла в коде макроса
        💹 VBA_May_Call_DLL_Using_XLM_XLF - Обнаружение вызова DLL через Excel 4 Macros (XLM/XLF)
        💹 VBA_May_Create_OLE_Object - Обнаружение создания OLE-объекта
        💹 VBA_May_Run_Code_From_DLL - Обнаружение вызова кода из DLL
        💹 VBA_May_Self_Modify_VBA_Code - Обнаружение попытки самомодификации кода макроса

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\4bdff89b4a48bc4f1910711cdba901a7ab94d7a5b13f07dbe8f0fa827d30dc58.docm
🔍 Сработавшие правила:
💹 Contains_VBA_macro_code - Обнаружение MS Office документа с встроенным VBA макросом

        Обнаружены макросы в файле: D:\yara\phishing-yara\malware\doc\4bdff89b4a48bc4f1910711cdba901a7ab94d7a5b13f07dbe8f0fa827d30dc58.docm
        🔍 Сработавшие правила:
        💹 VBA_Open_File - Обнаружение процесса открытия какого файла в коде макроса

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\4c1bc269ba7417d826e240aaa7087030ade34c3d22f07b09f80c39c90ad9ed84.xlsm
🔍 Сработавшие правила:
💹 Contains_VBA_macro_code - Обнаружение MS Office документа с встроенным VBA макросом
💹 VBA_May_Run_Code_From_DLL - Обнаружение вызова кода из DLL

        Обнаружены макросы в файле: D:\yara\phishing-yara\malware\doc\4c1bc269ba7417d826e240aaa7087030ade34c3d22f07b09f80c39c90ad9ed84.xlsm
        🔍 Сработавшие правила:
        💹 VBA_Read_System_Environment_Variables -
        💹 VBA_Open_File - Обнаружение процесса открытия какого файла в коде макроса
        💹 VBA_May_Write_to_file - Обнаружение процесса записи чего-либо в файл в коде макроса
        💹 VBA_May_Read_Or_Write_Binary_File - Обнаружение процесса чтения или записи бинарного файла в коде макроса
        💹 VBA_May_Copy_File - Обнаружение процесса копирования файлов в коде макроса
        💹 VBA_May_run_an_executable_file_or_a_system_command - Обнаружение запуска исполняемых файлов или системных команд в коде макроса
        💹 VBA_May_Run_PowerShell_Commands - Обнаружение запуска PowerShell-команд из макроса
        💹 VBA_May_Call_DLL_Using_XLM_XLF - Обнаружение вызова DLL через Excel 4 Macros (XLM/XLF)
        💹 VBA_May_Create_Directory - Обнаружение создания директории
        💹 VBA_May_Save_Workbook - Обнаружение сохранения рабочей книги
        💹 VBA_May_Create_OLE_Object - Обнаружение создания OLE-объекта
        💹 VBA_May_Run_Application_With_CreateObject - Обнаружение запуска приложения через Shell.Application
        💹 VBA_May_Enumerate_Windows - Обнаружение перебора окон приложения
        💹 VBA_May_Run_Code_From_DLL - Обнаружение вызова кода из DLL
        💹 VBA_May_Download_Files_From_Internet - Обнаружение загрузки файлов из интернета
        💹 VBA_May_Download_Files_From_Internet_Using_PowerShell - Обнаружение загрузки файлов из интернета через PowerShell
        💹 VBA_May_Control_Another_Application_By_Keystrokes - Обнаружение управления другим приложением через эмуляцию нажатий клавиш
        💹 VBA_May_Obfuscate_Strings - Обнаружение попытки обфускации строк
        💹 VBA_May_Detect_Norman_Sandbox - Обнаружение Norman Sandbox
        💹 VBA_May_Self_Modify_VBA_Code - Обнаружение попытки самомодификации кода макроса

        IOC's:
        -: http://www.frez.co.uk (URL)
        -: https://drive.google.com/uc?export=download&id=1SW1Zwx-yecxgONA0AXSRDkBJfBEOKl4c (URL)
        -: http://tinyurl.com/y8rn79da (URL)
        -: https://exceloffthegrid.com/vba-cod-to-zip-unzip (URL)
        -: http://exceldevelopmentplatform.blogspot.com/2018/01/vba-winhttprequest-no-asynchronous.html (URL)
        -: User32.dll (Executable file name)
        -: chrome.exe (Executable file name)
        -: firefox.exe (Executable file name)
        -: winhttpcom.dll (Executable file name)

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\525dca66603ba93785836da140e8bf75d86a71ce828d30797171a3989e1dee51.xlsm
🔍 Сработавшие правила:
💹 Contains_VBA_macro_code - Обнаружение MS Office документа с встроенным VBA макросом

        Обнаружены макросы в файле: D:\yara\phishing-yara\malware\doc\525dca66603ba93785836da140e8bf75d86a71ce828d30797171a3989e1dee51.xlsm
        🔍 Сработавшие правила:
        💹 VBA_Read_System_Environment_Variables -
        💹 VBA_Open_File - Обнаружение процесса открытия какого файла в коде макроса
        💹 VBA_May_Write_to_file - Обнаружение процесса записи чего-либо в файл в коде макроса
        💹 VBA_May_Read_Or_Write_Binary_File - Обнаружение процесса чтения или записи бинарного файла в коде макроса
        💹 VBA_May_run_an_executable_file_or_a_system_command - Обнаружение запуска исполняемых файлов или системных команд в коде макроса
        💹 VBA_May_Run_PowerShell_Commands - Обнаружение запуска PowerShell-команд из макроса
        💹 VBA_May_Call_DLL_Using_XLM_XLF - Обнаружение вызова DLL через Excel 4 Macros (XLM/XLF)
        💹 VBA_May_Create_Directory - Обнаружение создания директории
        💹 VBA_May_Create_OLE_Object - Обнаружение создания OLE-объекта
        💹 VBA_May_Run_Code_From_DLL - Обнаружение вызова кода из DLL
        💹 VBA_May_Download_Files_From_Internet - Обнаружение загрузки файлов из интернета
        💹 VBA_May_Download_Files_From_Internet_Using_PowerShell - Обнаружение загрузки файлов из интернета через PowerShell
        💹 VBA_May_Obfuscate_Strings - Обнаружение попытки обфускации строк

        IOC's:
        -: https://tursiian.com/7z.txt (URL)
        -: https://f004.backblazeb2.com/file/mdocument/PO202502DAKE.zip (URL)
        -: 7z.exe (Executable file name)
        -: 7zip_installer.exe (Executable file name)
        -: 2.dll (Executable file name)
        -: msvcp290.dll (Executable file name)
        -: nasrallah_x86.dll (Executable file name)
        -: vcruntime210.dll (Executable file name)
        -: PO202502DAKE.exe (Executable file name)
        -: regsvr32.exe (Executable file name)

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\59657f4537018aa3621450282e9a973895e33e6f236f4f644769a505c498c004.docm
🔍 Сработавшие правила:
💹 Contains_VBA_macro_code - Обнаружение MS Office документа с встроенным VBA макросом

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\5d12f3d6b8c0418215b29ad3afb0a3448966a6eaeb02dca2e89d6bff5d8e2570.xlsm
🔍 Сработавшие правила:
💹 Contains_VBA_macro_code - Обнаружение MS Office документа с встроенным VBA макросом

        Обнаружены макросы в файле: D:\yara\phishing-yara\malware\doc\5d12f3d6b8c0418215b29ad3afb0a3448966a6eaeb02dca2e89d6bff5d8e2570.xlsm
        🔍 Сработавшие правила:
        💹 VBA_Read_System_Environment_Variables -
        💹 VBA_Open_File - Обнаружение процесса открытия какого файла в коде макроса
        💹 VBA_May_Write_to_file - Обнаружение процесса записи чего-либо в файл в коде макроса
        💹 VBA_May_Read_Or_Write_Binary_File - Обнаружение процесса чтения или записи бинарного файла в коде макроса
        💹 VBA_May_run_an_executable_file_or_a_system_command - Обнаружение запуска исполняемых файлов или системных команд в коде макроса
        💹 VBA_May_Run_PowerShell_Commands - Обнаружение запуска PowerShell-команд из макроса
        💹 VBA_May_Call_DLL_Using_XLM_XLF - Обнаружение вызова DLL через Excel 4 Macros (XLM/XLF)
        💹 VBA_May_Create_Directory - Обнаружение создания директории
        💹 VBA_May_Create_OLE_Object - Обнаружение создания OLE-объекта
        💹 VBA_May_Run_Code_From_DLL - Обнаружение вызова кода из DLL
        💹 VBA_May_Download_Files_From_Internet - Обнаружение загрузки файлов из интернета
        💹 VBA_May_Download_Files_From_Internet_Using_PowerShell - Обнаружение загрузки файлов из интернета через PowerShell
        💹 VBA_May_Obfuscate_Strings - Обнаружение попытки обфускации строк

        IOC's:
        -: https://tursiian.com/7z.txt (URL)
        -: https://f005.backblazeb2.com/file/newuploavir/newpoveno.zip (URL)
        -: 7z.exe (Executable file name)
        -: 7zip_installer.exe (Executable file name)
        -: 2.dll (Executable file name)
        -: msvcp290.dll (Executable file name)
        -: nasrallah_x86.dll (Executable file name)
        -: vcruntime210.dll (Executable file name)
        -: newpoveno.exe (Executable file name)
        -: regsvr32.exe (Executable file name)

Совпадений в файле D:\yara\phishing-yara\malware\doc\6782b1a05b867003e5bcfc30375f1770b8fc417e785919d0dfd827113df7c91a.doc не ОБНАРУЖЕНО

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\762639e3f486ec2e049a4608d2258321e415d7775bbdd7a9f755c80cebd2e978.xlsm
🔍 Сработавшие правила:
💹 Contains_VBA_macro_code - Обнаружение MS Office документа с встроенным VBA макросом

        Обнаружены макросы в файле: D:\yara\phishing-yara\malware\doc\762639e3f486ec2e049a4608d2258321e415d7775bbdd7a9f755c80cebd2e978.xlsm
        🔍 Сработавшие правила:
        💹 VBA_Read_System_Environment_Variables -
        💹 VBA_Open_File - Обнаружение процесса открытия какого файла в коде макроса
        💹 VBA_May_Write_to_file - Обнаружение процесса записи чего-либо в файл в коде макроса
        💹 VBA_May_Read_Or_Write_Binary_File - Обнаружение процесса чтения или записи бинарного файла в коде макроса
        💹 VBA_May_Copy_File - Обнаружение процесса копирования файлов в коде макроса
        💹 VBA_May_run_an_executable_file_or_a_system_command - Обнаружение запуска исполняемых файлов или системных команд в коде макроса
        💹 VBA_May_Run_PowerShell_Commands - Обнаружение запуска PowerShell-команд из макроса
        💹 VBA_May_Call_DLL_Using_XLM_XLF - Обнаружение вызова DLL через Excel 4 Macros (XLM/XLF)
        💹 VBA_May_Create_Directory - Обнаружение создания директории
        💹 VBA_May_Save_Workbook - Обнаружение сохранения рабочей книги
        💹 VBA_May_Create_OLE_Object - Обнаружение создания OLE-объекта
        💹 VBA_May_Run_Application_With_CreateObject - Обнаружение запуска приложения через Shell.Application
        💹 VBA_May_Enumerate_Windows - Обнаружение перебора окон приложения
        💹 VBA_May_Run_Code_From_DLL - Обнаружение вызова кода из DLL
        💹 VBA_May_Download_Files_From_Internet - Обнаружение загрузки файлов из интернета
        💹 VBA_May_Download_Files_From_Internet_Using_PowerShell - Обнаружение загрузки файлов из интернета через PowerShell
        💹 VBA_May_Control_Another_Application_By_Keystrokes - Обнаружение управления другим приложением через эмуляцию нажатий клавиш
        💹 VBA_May_Obfuscate_Strings - Обнаружение попытки обфускации строк
        💹 VBA_May_Detect_Norman_Sandbox - Обнаружение Norman Sandbox
        💹 VBA_May_Self_Modify_VBA_Code - Обнаружение попытки самомодификации кода макроса

        IOC's:
        -: http://www.frez.co.uk (URL)
        -: https://drive.google.com/uc?export=download&id=1SW1Zwx-yecxgONA0AXSRDkBJfBEOKl4c (URL)
        -: http://tinyurl.com/y8rn79da (URL)
        -: https://exceloffthegrid.com/vba-cod-to-zip-unzip (URL)
        -: http://exceldevelopmentplatform.blogspot.com/2018/01/vba-winhttprequest-no-asynchronous.html (URL)
        -: User32.dll (Executable file name)
        -: chrome.exe (Executable file name)
        -: firefox.exe (Executable file name)
        -: winhttpcom.dll (Executable file name)

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\7637a06005c3e90cedae65054c0458d02a66865e1f91c61b5b7ba1ccf3303587.xlsm
🔍 Сработавшие правила:
💹 Contains_VBA_macro_code - Обнаружение MS Office документа с встроенным VBA макросом
💹 VBA_May_run_an_executable_file_or_a_system_command - Обнаружение запуска исполняемых файлов или системных команд в коде макроса
💹 VBA_May_Run_Code_From_DLL - Обнаружение вызова кода из DLL
💹 VBA_May_Obfuscate_Strings - Обнаружение попытки обфускации строк

        Обнаружены макросы в файле: D:\yara\phishing-yara\malware\doc\7637a06005c3e90cedae65054c0458d02a66865e1f91c61b5b7ba1ccf3303587.xlsm
        🔍 Сработавшие правила:
        💹 VBA_Open_File - Обнаружение процесса открытия какого файла в коде макроса
        💹 VBA_May_Write_to_file - Обнаружение процесса записи чего-либо в файл в коде макроса
        💹 VBA_May_run_an_executable_file_or_a_system_command - Обнаружение запуска исполняемых файлов или системных команд в коде макроса
        💹 VBA_May_Run_PowerShell_Commands - Обнаружение запуска PowerShell-команд из макроса
        💹 VBA_May_Run_Executable_or_System_Command_Using_PowerShell - Обнаружение запуска исполняемого файла или системной команды через PowerShell
        💹 VBA_May_Create_OLE_Object - Обнаружение создания OLE-объекта
        💹 VBA_May_Enumerate_Windows - Обнаружение перебора окон приложения

        IOC's:
        -: http://3.73.132.53/hz/Etolfsojm.exe (URL)
        -: 3.73.132.53 (IPv4 address)
        -: Etolfsojm.exe (Executable file name)

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\80bc491f53143f0586753066eff8912b356258afe443f5d0f74ef9b36703225c.xlsm
🔍 Сработавшие правила:
💹 Contains_VBA_macro_code - Обнаружение MS Office документа с встроенным VBA макросом

        Обнаружены макросы в файле: D:\yara\phishing-yara\malware\doc\80bc491f53143f0586753066eff8912b356258afe443f5d0f74ef9b36703225c.xlsm
        🔍 Сработавшие правила:
        💹 VBA_Read_System_Environment_Variables -
        💹 VBA_Open_File - Обнаружение процесса открытия какого файла в коде макроса
        💹 VBA_May_Write_to_file - Обнаружение процесса записи чего-либо в файл в коде макроса
        💹 VBA_May_run_an_executable_file_or_a_system_command - Обнаружение запуска исполняемых файлов или системных команд в коде макроса
        💹 VBA_May_Run_PowerShell_Commands - Обнаружение запуска PowerShell-команд из макроса
        💹 VBA_May_Call_DLL_Using_XLM_XLF - Обнаружение вызова DLL через Excel 4 Macros (XLM/XLF)
        💹 VBA_May_Create_OLE_Object - Обнаружение создания OLE-объекта
        💹 VBA_May_Download_Files_From_Internet - Обнаружение загрузки файлов из интернета
        💹 VBA_May_Obfuscate_Strings - Обнаружение попытки обфускации строк

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\8f1a239bf3b70a9511bf43adb7c5d4b692656b63c2e162973a197b74b7d40d6f.xlsm
🔍 Сработавшие правила:
💹 Contains_VBA_macro_code - Обнаружение MS Office документа с встроенным VBA макросом
💹 VBA_May_Run_Code_From_DLL - Обнаружение вызова кода из DLL

        Обнаружены макросы в файле: D:\yara\phishing-yara\malware\doc\8f1a239bf3b70a9511bf43adb7c5d4b692656b63c2e162973a197b74b7d40d6f.xlsm
        🔍 Сработавшие правила:
        💹 VBA_Open_File - Обнаружение процесса открытия какого файла в коде макроса
        💹 VBA_May_Write_to_file - Обнаружение процесса записи чего-либо в файл в коде макроса
        💹 VBA_May_run_an_executable_file_or_a_system_command - Обнаружение запуска исполняемых файлов или системных команд в коде макроса
        💹 VBA_May_Run_PowerShell_Commands - Обнаружение запуска PowerShell-команд из макроса
        💹 VBA_May_Run_Executable_or_System_Command_Using_PowerShell - Обнаружение запуска исполняемого файла или системной команды через PowerShell
        💹 VBA_May_Create_OLE_Object - Обнаружение создания OLE-объекта
        💹 VBA_May_Enumerate_Windows - Обнаружение перебора окон приложения

        IOC's:
        -: https://dikatafarm.co.za/lika/may30.exe (URL)
        -: may30.exe (Executable file name)

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\99a2af2b1d39d3ca267095cc733dd5e285b40b9c6b1709d34dbb213387c8df93.xlsm
🔍 Сработавшие правила:
💹 Contains_VBA_macro_code - Обнаружение MS Office документа с встроенным VBA макросом
💹 VBA_May_Run_Code_From_DLL - Обнаружение вызова кода из DLL

        Обнаружены макросы в файле: D:\yara\phishing-yara\malware\doc\99a2af2b1d39d3ca267095cc733dd5e285b40b9c6b1709d34dbb213387c8df93.xlsm
        🔍 Сработавшие правила:
        💹 VBA_Open_File - Обнаружение процесса открытия какого файла в коде макроса
        💹 VBA_May_Write_to_file - Обнаружение процесса записи чего-либо в файл в коде макроса
        💹 VBA_May_run_an_executable_file_or_a_system_command - Обнаружение запуска исполняемых файлов или системных команд в коде макроса
        💹 VBA_May_Run_PowerShell_Commands - Обнаружение запуска PowerShell-команд из макроса
        💹 VBA_May_Run_Executable_or_System_Command_Using_PowerShell - Обнаружение запуска исполняемого файла или системной команды через PowerShell
        💹 VBA_May_Create_OLE_Object - Обнаружение создания OLE-объекта
        💹 VBA_May_Enumerate_Windows - Обнаружение перебора окон приложения

        IOC's:
        -: https://mindfree.co.za/1/Recrypted.pif (URL)
        -: Recrypted.pif (Executable file name)

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\bbff2bce7c553d1e11b48a38bfd351f9e715b683171f596751d78ace10782e79.xlsm
🔍 Сработавшие правила:
💹 Contains_VBA_macro_code - Обнаружение MS Office документа с встроенным VBA макросом

        Обнаружены макросы в файле: D:\yara\phishing-yara\malware\doc\bbff2bce7c553d1e11b48a38bfd351f9e715b683171f596751d78ace10782e79.xlsm
        🔍 Сработавшие правила:
        💹 VBA_Open_File - Обнаружение процесса открытия какого файла в коде макроса
        💹 VBA_May_Write_to_file - Обнаружение процесса записи чего-либо в файл в коде макроса
        💹 VBA_May_run_an_executable_file_or_a_system_command - Обнаружение запуска исполняемых файлов или системных команд в коде макроса
        💹 VBA_May_Create_OLE_Object - Обнаружение создания OLE-объекта

        IOC's:
        -: http://193.203.203.67/rt/Doc-3737122pdf.exe (URL)
        -: 193.203.203.67 (IPv4 address)
        -: 3737122pdf.exe (Executable file name)

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\c2macro.xlsm
🔍 Сработавшие правила:
💹 Contains_VBA_macro_code - Обнаружение MS Office документа с встроенным VBA макросом

        Обнаружены макросы в файле: D:\yara\phishing-yara\malware\doc\c2macro.xlsm
        🔍 Сработавшие правила:
        💹 VBA_Using_System_Process - Обнаружение использования легитимных системных процессов для выполнения вредоносного кода
        💹 VBA_Process_Create - Обнаружение создание другого процесса в коде VBA макроса
        💹 VBA_Read_System_Environment_Variables -
        💹 VBA_Open_File - Обнаружение процесса открытия какого файла в коде макроса
        💹 VBA_May_Write_to_file - Обнаружение процесса записи чего-либо в файл в коде макроса
        💹 VBA_May_run_an_executable_file_or_a_system_command - Обнаружение запуска исполняемых файлов или системных команд в коде макроса
        💹 VBA_May_Run_PowerShell_Commands - Обнаружение запуска PowerShell-команд из макроса
        💹 VBA_May_Hide_Application - Обнаружение попытки скрыть приложение
        💹 VBA_May_Run_Code_From_DLL - Обнаружение вызова кода из DLL
        💹 VBA_May_Inject_Code_Into_Another_Process - Обнаружение внедрения кода в другой процесс
        💹 VBA_May_Detect_Virtualization - Обнаружение признаков виртуализации

        IOC's:
        -: rundll32.exe (Executable file name)

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\c59b2d6a70bc5b84998aebb2d21241a8adef33724838e92db4dee36a1ce46f43.docm
🔍 Сработавшие правила:
💹 Contains_VBA_macro_code - Обнаружение MS Office документа с встроенным VBA макросом
💹 VBA_May_run_an_executable_file_or_a_system_command - Обнаружение запуска исполняемых файлов или системных команд в коде макроса
💹 VBA_May_Run_Code_From_DLL - Обнаружение вызова кода из DLL
💹 VBA_May_Obfuscate_Strings - Обнаружение попытки обфускации строк

        Обнаружены макросы в файле: D:\yara\phishing-yara\malware\doc\c59b2d6a70bc5b84998aebb2d21241a8adef33724838e92db4dee36a1ce46f43.docm
        🔍 Сработавшие правила:
        💹 VBA_Read_System_Environment_Variables -
        💹 VBA_Open_File - Обнаружение процесса открытия какого файла в коде макроса
        💹 VBA_May_Write_to_file - Обнаружение процесса записи чего-либо в файл в коде макроса
        💹 VBA_May_Copy_File - Обнаружение процесса копирования файлов в коде макроса
        💹 VBA_May_run_an_executable_file_or_a_system_command - Обнаружение запуска исполняемых файлов или системных команд в коде макроса
        💹 VBA_May_Call_DLL_Using_XLM_XLF - Обнаружение вызова DLL через Excel 4 Macros (XLM/XLF)
        💹 VBA_May_Create_Directory - Обнаружение создания директории
        💹 VBA_May_Create_OLE_Object - Обнаружение создания OLE-объекта
        💹 VBA_May_Run_Application_With_CreateObject - Обнаружение запуска приложения через Shell.Application

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\dbf93e49421127168a80a7f036572651124bb3e754d3b35bb3a8849461041ddc.xlsm
🔍 Сработавшие правила:
💹 Contains_VBA_macro_code - Обнаружение MS Office документа с встроенным VBA макросом

        Обнаружены макросы в файле: D:\yara\phishing-yara\malware\doc\dbf93e49421127168a80a7f036572651124bb3e754d3b35bb3a8849461041ddc.xlsm
        🔍 Сработавшие правила:
        💹 VBA_Read_System_Environment_Variables -
        💹 VBA_Open_File - Обнаружение процесса открытия какого файла в коде макроса
        💹 VBA_May_Write_to_file - Обнаружение процесса записи чего-либо в файл в коде макроса
        💹 VBA_May_Read_Or_Write_Binary_File - Обнаружение процесса чтения или записи бинарного файла в коде макроса
        💹 VBA_May_run_an_executable_file_or_a_system_command - Обнаружение запуска исполняемых файлов или системных команд в коде макроса
        💹 VBA_May_Run_PowerShell_Commands - Обнаружение запуска PowerShell-команд из макроса
        💹 VBA_May_Call_DLL_Using_XLM_XLF - Обнаружение вызова DLL через Excel 4 Macros (XLM/XLF)
        💹 VBA_May_Create_Directory - Обнаружение создания директории
        💹 VBA_May_Create_OLE_Object - Обнаружение создания OLE-объекта
        💹 VBA_May_Run_Code_From_DLL - Обнаружение вызова кода из DLL
        💹 VBA_May_Download_Files_From_Internet - Обнаружение загрузки файлов из интернета
        💹 VBA_May_Download_Files_From_Internet_Using_PowerShell - Обнаружение загрузки файлов из интернета через PowerShell
        💹 VBA_May_Obfuscate_Strings - Обнаружение попытки обфускации строк

        IOC's:
        -: https://tursiian.com/7z.txt (URL)
        -: https://f004.backblazeb2.com/file/mdocument/PO202502SNAKWS.zip (URL)
        -: 7z.exe (Executable file name)
        -: 7zip_installer.exe (Executable file name)
        -: 2.dll (Executable file name)
        -: msvcp290.dll (Executable file name)
        -: nasrallah_x86.dll (Executable file name)
        -: vcruntime210.dll (Executable file name)
        -: PO202502SNAKWS.exe (Executable file name)
        -: regsvr32.exe (Executable file name)

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\e33f2f65cb6c105bc22d0aaf0ec576fe3e4b3f3634276921eabdd221817f3da6.xlsm
🔍 Сработавшие правила:
💹 Contains_VBA_macro_code - Обнаружение MS Office документа с встроенным VBA макросом

        Обнаружены макросы в файле: D:\yara\phishing-yara\malware\doc\e33f2f65cb6c105bc22d0aaf0ec576fe3e4b3f3634276921eabdd221817f3da6.xlsm
        🔍 Сработавшие правила:
        💹 VBA_May_Create_OLE_Object - Обнаружение создания OLE-объекта

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\exploited.doc
🔍 Сработавшие правила:
💹 VBA_May_Enumerate_Windows - Обнаружение перебора окон приложения
💹 VBA_May_Obfuscate_Strings - Обнаружение попытки обфускации строк

Найдено совпадение в файле: D:\yara\phishing-yara\malware\doc\reverse_shell.docm
🔍 Сработавшие правила:
💹 Contains_VBA_macro_code - Обнаружение MS Office документа с встроенным VBA макросом
💹 VBA_May_Obfuscate_Strings - Обнаружение попытки обфускации строк

        Обнаружены макросы в файле: D:\yara\phishing-yara\malware\doc\reverse_shell.docm
        🔍 Сработавшие правила:
        💹 VBA_Potential_Persistence_Startup_Detected - Обнаружение попытки закрепления в папке автозагрузки Windows
        💹 VBA_Open_File - Обнаружение процесса открытия какого файла в коде макроса
        💹 VBA_May_Write_to_file - Обнаружение процесса записи чего-либо в файл в коде макроса
        💹 VBA_May_Read_Or_Write_Binary_File - Обнаружение процесса чтения или записи бинарного файла в коде макроса
        💹 VBA_May_Enumerate_Windows - Обнаружение перебора окон приложения

        IOC's:
        -: DnsSystem.exe (Executable file name)
```

---
## Результаты и выводы

В ходе работы создана система, способная выявлять вредоносные вложения и макросы, используемые в фишинговых атаках, что позволяет значительно повысить уровень защиты корпоративных и персональных почтовых систем. Использование YARA обеспечивает гибкость и масштабируемость решения.

---

*Данный проект является частью дипломной работы по теме противодействия фишинговым атакам и направлен на практическое применение современных методов кибербезопасности.*
