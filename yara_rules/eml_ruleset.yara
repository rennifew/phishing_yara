private rule IS_Mail {
  meta:
    description = "Файл является письмом EML"
  strings:
    $eml_01 = "From:"
    $eml_02 = "To:"
    $eml_03 = "Subject:"
  condition:
    all of them
}

rule Mail_with_attachment {
  meta:
    description = "Письмо содержит вложения"

  strings:
    $attachment_id = "X-Attachment-Id"
    $attachment = "attachment"

  condition:
    IS_Mail and any of them
}

rule Suspicious_Attachment_Extensions {
  meta:
    description = "Обнаружение вложения с необычным и потенциально опасным расширением"

  strings:
    $rdp = ".rdp" nocase
    $lnk = ".lnk" nocase
    $exe = ".exe" nocase
    $bat = ".bat" nocase
    $cmd = ".cmd" nocase
    $ps1 = ".ps1" nocase
    $scr = ".scr" nocase
    $vbs = ".vbs" nocase
    $js = ".js" nocase
    $jar = ".jar" nocase
    $msi = ".msi" nocase
    $hta = ".hta" nocase
    $com = ".com" nocase
    $pif = ".pif" nocase
    $zip = ".zip" nocase
    $7z = ".7z" nocase

  condition:
    IS_Mail and Mail_with_attachment and any of them
}


rule Mail_with_urls: mail {
  meta:
    description = "Письмо содержит ссылки"

  strings:
    $url_regex = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/

  condition:
    IS_Mail and $url_regex
}

rule Mail_With_Hidden_Links {
  meta:
    description = "Письмо содержит скрытые ссылки"
  strings:
    $hidden_http = "<http"
  condition:
    IS_Mail and Mail_with_urls and $hidden_http
}

rule Out_Mail_Detected {
  meta:
    description = "Письмо пришло от внешнего почтового сервера."
  strings:
    $vneshn_pochta = "=D0=92=D0=BD=D0=B5=D1=88=D0=BD=D1=8F=D1=8F =D0=BF=D0=BE=D1=87=D1=82=D0=B0" // Внешняя почта 
    $vnesh = "=D0=92=D0=9D=D0=95=D0=A8=D0=9D=D0=AF=D0=AF =D0=9F=D0=9E=D0=A7=D0=A2=D0=90" // ВНЕШНЯЯ ПОЧТА
  condition:
    IS_Mail and any of them
}

rule Mail_Contains_Social_Engineering {
  meta:
    description = "Письмо содержит популярные фразы, которые принуждают получателя к действию."
  strings:
    $ = "=D0=A1=D1=80=D0=BE=D1=87=D0=BD=" // Срочно 
    $ = "=D1=81=D1=80=D0=BE=D1=87=D0=BD=D0=BE" // cрочно 
    $ = "=D0=91=D1=8B=D1=81=D1=82=D1=80=D0=B5=D0=B5" // Быстрее 
    $ = "=D0=B1=D1=8B=D1=81=D1=82=D1=80=D0=B5=D0=B5" // быстрее 
    $ = "=D1=80=D0=BE=D0=BA =D0=B4=D0=B5=D0=B9=D1=81=D1=82=D0=B2=D0=B8=D1=8F" // Срок действия 
    $ = "=D0=A2=D1=80=D0=B5=D0=B1=D1=83=D0=B5=D1=82=D1=81=D1=8F =D0=B2=D0=B0=D1=88=D0=B5 =D1=80=D0=B5=D1=88=D0=B5=D0=BD=D0=B8=D0=B5" // Требуется ваше решение 
    $ = "=D0=A1=D1=82=D0=B0=D1=82=D1=83=D1=81 =D0=BF=D0=BB=D0=B0=D1=82=D0=B5=D0=B6=D0=B0" // Статус платежа 
    $ = "=D0=9F=D0=BE=D0=B4=D1=82=D0=B2=D0=B5=D1=80=D0=B4=D0=B8=D1=82=D0=B5" // Подтвердите
    $ = "=D0=9F=D0=BE=D0=B4=D1=82=D0=B2=D0=B5=D1=80=D0=B4=D0=B8=D1=82=D0=B5 =D0=B4=D0=B0=D0=BD=D0=BD=D1=8B=D0=B5" // Подтвердите данные
    $ = "=D0=9E=D1=82=D0=BA=D1=80=D1=8B=D1=82=D1=8C" // Открыть
    $ = "=D0=9F=D0=B5=D1=80=D0=B5=D0=B9=D1=82=D0=B8" // Перейти
    $ = "=D0=9E=D0=BF=D0=BB=D0=B0=D1=82=D0=B8=D1=82=D1=8C" // Оплатить
    $ = "=D0=9E=D0=BF=D0=BB=D0=B0=D1=82=D0=B0" // Оплата
    $ = "=D0=92=D0=BD=D0=B8=D0=BC=D0=B0=D0=BD=D0=B8=D0=B5" // Внимание
    $ = "=D0=9F=D1=80=D0=B5=D0=B4=D1=83=D0=BF=D1=80=D0=B5=D0=B6=D0=B4=D0=B5=D0=BD=D0=B8=D0=B5" // Предупреждение
    $ = "=D0=9D=D0=B5=D0=BE=D1=82=D0=BB=D0=B0=D0=B6=D0=BD=D0=BE" // Неотложно
    $ = "=D0=9F=D1=80=D0=BE=D1=81=D1=82=D0=BE=D0=B9=D1=82=D0=B5" // Проверьте
    $ = "=D0=9F=D1=80=D0=BE=D0=B2=D0=B5=D1=80=D0=BA=D0=B0" // Проверка
    $ = "=D0=9F=D0=BE=D0=B4=D1=82=D0=B2=D0=B5=D1=80=D0=B4=D0=B8=D1=82=D0=B5 =D0=BF=D0=BE=D1=80=D1=82=D1=84=D0=B5=D0=BB=D1=8C" // Подтвердите портфель
    $ = "=D0=9E=D0=B1=D0=BD=D0%BE=D0=B2=D0=B8=D1=82=D1=8C" // Обновить
    $ = "=D0=9E=D0=B1=D0=BD=D0%BE=D0=B2=D0=BB=D0=B5=D0=BD=D0=B8=D0=B5" // Обновление
    $ = "=D0=9F=D1=80=D0=BE=D1=81=D1=80=D0=BE=D1=87=D0=BD=D0=BE" // Просрочно
    $ = "=D0=9F=D1=80=D0=BE=D1=81=D1=80=D0=BE=D1=87=D0=BD=D0=B0=D1=8F" // Просрочная
    $ = "=D0=9F=D0=BE=D0=B2=D1=82=D0=BE=D1=80=D0=B0" // Повтора
    $ = "=D0=9F=D0=BE=D0=B2=D1=82=D0=BE=D1=80=D0=B8=D1=82=D1=8C" // Повторить
    $ = "=D0=9F=D0=BE=D0=B2=D1=82=D0=BE=D1=80=D0=B8=D1=82=D0=B5" // Повторите
  condition:
    IS_Mail and any of them
}

