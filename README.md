#  Сервис авторизации

## Общая информация

Сервис сделан в рамках обучения middle python-разработчик на practicum.yandex.ru

API для получения авторизации, установки ролей и доступов. 

Реализовано на Flask. В качестве базы данных используется Postgres, в качестве кеша - Redis.

Подробности про методы и аргументы - см. `http://HOST:PORT/api/v1/swagger-ui/`

### Технологии

![Redis](https://img.shields.io/badge/redis-%23DD0031.svg?style=for-the-badge&logo=redis&logoColor=white)
![Postgres](https://img.shields.io/badge/postgres-%23316192.svg?style=for-the-badge&logo=postgresql&logoColor=white)
![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white)
![Nginx](https://img.shields.io/badge/nginx-%23009639.svg?style=for-the-badge&logo=nginx&logoColor=white)
## Запуск

Для запуска отдельно AuthAPI-сервиса можно использовать Dockerfile (предполагая, что у нас уже есть развёрнутый Postgres и прочая инфраструктура, и нужен только сам сервис) или через app.py. Используется порт 5000.

Для поднятия всего нужного окружения сразу можно использовать docker-compose (включает в себя сам сервис, Redis, Postgres и nginx). В этом случае используется порт 80 (nginx).

Можно использовать Make flask_local. Запускает Redis, Postgres в Docker-Compose и Flask локально. Swagger документация доступна по адресу 127.0.0.1:5000/api/v1/swagger_ui/

 ## Реализовано

* Авторизация через Яндекс или VK auth

* Circuit breakers. Если при запросе возникает ошибка, то делает перенаправление.
После `FAIL_MAX` запросов перестает отправлять запросы
и сразу делает перенаправление в течении `RESET_TIMEOUT`

* Rate limit - Ограничение количества запросов с 1 IP в мин.

* Двухфакторная аутентификация TOTP.

* Возможность создать на сервере супер-админа, у которого нет ограничения на доступ по ролям.
Команда `Create super_user "email" "password"`

## Ограничение прав API
В JWT токене содержится роль пользователя, для проверки доступа по ролям без запроса к БД

Ограничения можно устанавливать как по ролям, так и по правам.

В требуемых правах содержится список прав, который можно изменять по API.
Есть возможность установить ограничение на доступ при наличии хотя бы 1 права у пользователя из списка требуемых
или требовать только 1

## Документация

После запуска доступна по адресам:
* http://HOST/api/v1/swagger_ui

##  История входов

В истории входов юзера отображается User Agent пользователя и дата первого входа. 
Не ведется время и учет количества входов с 1 устройства. Только факт входа с устройства. 
При выходе юзер агент удаляется и невозможно получить новый access токен при запросе с refresh токеном.
 http://HOST/api/v1/user/history

## JWT 

Для создания secret key и public можно воспользоваться командой `make create_jwt_key`, которая создает 2 файла с открытым и закрытым ключами.
Ключи необходимо прописать в настройках или в переменных при создании Docker-compose.

* JWT token содержит список ролей, по открытому ключю можно проверить его подлинность 

* Api для получения открытого ключа  http://127.0.0.1/api/v1/auth/open-token

* Cсылка на FastApi https://github.com/AntonRev/Async_API. В сервисе для эндпоинта `api/v1/films` добавлена проверка токена и роли в токене. Если нет необходимой роли выдается ограниченное количество фильмов.
