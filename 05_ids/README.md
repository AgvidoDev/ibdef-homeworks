# Мониторинг сетевых событий (Suricata)

В качестве результата пришлите ответы на вопросы в личном кабинете студента на сайте [netology.ru](https://netology.ru/).

## 

### Задание 1

Напишите правило для детектирования Xmas-сканирования.

*Дайте ответ в свободной форме.*

------


```
alert tcp any any -> $HOME_NET any ( \
    msg:"Xmas Scan"; \   
    flow:stateless; \
    flags:FPU; \   # Детектирует пакеты с флагами: FIN (F), PSH (P), URG (U)
    threshold: type threshold, track by_src, count 3, seconds 60; \ # от 3+ пакетов с одного источника в течении 60 секунд
    reference:url,doc.emergingthreats.net/2001976; \
    classtype:attempted-recon; \
    sid:2001976; \
    rev:1; \
)
```




### Задание 2

Напишите правило для детектирования стороннего трафика, передающегося службой DNS.

*Дайте ответ в свободной форме.*

------
В интернете нашел информацию, что надо идти по нескольким направлениям:
1. Проверка подозрительных доменов (от 50 символов)
2. Детектирование ТХТ  запросов с данными
3. Обнаружение большого кол-ва запросов к одниму домену
4. Фильтрацию по географическому расположению DNS-серверов
```
alert dns any any -> any any ( \
    msg:"ET POLICY Advanced DNS Tunneling Detection - Netology.ru"; \
    flow:to_server; \
    dns.query; \
    content:"netology.ru"; nocase; \
    dns.query.length:>50; \  # длина домена более 50 символов
    ( \
      dns.query; content:!"www."; content:!"mail."; content:!"api."; content:!"static."; nocase; \ # Исключает стандартные поддомены
      or \
      dns.query; pcre:"/[a-f0-9]{16,}\.netology\.ru$/i"; \ # Ищет HEX-поддомены
      or \
      dns.dns_type:16; dns.query; content:!"v=spf1"; \  # Фильтрует записи типа TXT (dns_type:16) и исключает стандартные SPF-записи
    ); \
    geoip:!country:RU; \ # срабатывает только на запросы вне России
    threshold: type threshold, track by_src, count 3, seconds 60; \
    reference:url,www.netology.ru/security/dns-threats; \
    reference:url,help.netology.ru/security/ids-rules; \
    classtype:attempted-dns-tunneling; \
    sid:2024001; \
    rev:1; \
   )
```


## Дополнительные задания со звёздочкой.

Эти задания необязательные. Их выполнение никак не влияет на получение зачёта по домашней работе. Вы можете их выполнить, если хотите усвоить полученный материал и лучше разобраться в теме.

------

### Задание 3*

Напишите правило для детектирования файлов или документов в сетевом трафике.

*Дайте ответ в свободной форме.*
