# Домашнее задание к занятию «Active Directory. Часть 1»

В качестве результата пришлите ответы на вопросы в личном кабинете студента на сайте [netology.ru](https://netology.ru/).

## 

### Задание 1

1. Скачайте и установите Windows Server 2019 (20162012), используя файл по [ссылке](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019). 

Настройка виртуальной машины.

Для пользователей с процессорами ARM (M Apple Silicon или другими) можно воспользоваться системой визуализации https://www.qemu.org/. 
Для Apple Mac — https://github.com/utmapp/UTM (docs https://docs.getutm.app/).

Для настройки виртуальной машины:
- два сетевых интерфейса: NAT и внутренняя сеть;
- оперативная память — 2–4 Гб.

2. Настройте Active Directory, используя материалы из открытых источников ниже:

- [материал 1](https://1cloud.ru/help/windows/active-directory-domain-services-ustanovka-i-nastrojka-windows-server);
- [материал 2](https://habr.com/ru/company/testo_lang/blog/525326/);
- [материал 3](https://efsol.ru/manuals/active-directory.html).

*Дайте ответ в виде снимков экрана.*
------

![ad01](ad01.jpg)
![ad03](ad03.jpg)


### Задание 2

Создайте в AD:

- пользователя `student1`, входящего в группу `students1`;
- пользователя `student2`, входящего в группу `students2`.

*Дайте ответ в виде снимков экрана.*

------

![ad02](ad02.jpg)
![ad04](ad04.jpg)
![ad05](ad05.jpg)



### Задание 3

- Создайте или используйте существующую ВМ с установленной ОС Windows и подключите к домену [ссылке](https://docs.microsoft.com/ru-ru/windows-server/identity/ad-fs/deployment/join-a-computer-to-a-domain);
- Зайдите под доменными учётными записями.

*Дайте ответ в виде снимков экрана.*

------

![ad06](ad06.jpg)
![ad07](ad07.jpg)
![ad08](ad08.jpg)
![ad09](ad09.jpg)


## Дополнительные задания со звёздочкой.

Эти задания необязательные.  Их выполнение никак не влияет на получение зачёта по домашней работе. Вы можете их выполнить, если хотите усвоить полученный материал и лучше разобраться в теме.

------

### Задание 4*

Настройте любую политику GPO и проверьте, что она распространилась на рабочую станцию:

- https://1cloud.ru/help/windows/gruppovye-politiki-active-directory;
- https://windowsnotes.ru/activedirectory/primenenie-gruppovyx-politik-chast-1/.

*Дайте ответ в виде снимков экрана.*
