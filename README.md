# ПЗ №10 — JWT аутентификация и авторизация

Сортов Семён Александрович, ЭФМО-01-26. Дата: 25.10.2026.

Реализованы /api/v1/login, /me, /admin/stats, /refresh и /users/{id}. В репозитории находятся две записи с bcrypt-хэшами: admin@example.com и user@example.com, пароль обеих записей — secret123, как в задании. Требуется Go 1.25+; проверено с Go 1.27.2 и golang-jwt/jwt/v5 5.3.1. Внешняя БД не нужна.

## Запуск

```powershell
go run ./cmd/keygen
$env:APP_PORT='8080'
$env:JWT_KEY_DIR='.keys'
$env:JWT_ACTIVE_KID='key2'
$env:JWT_TTL='15m'
$env:JWT_REFRESH_TTL='168h'
go run ./cmd/server
```

keygen создаёт две пары RSA-2048 и не перезаписывает существующие ключи. Каталог .keys исключён из Git. RS256 использует RSA-ключи; JWT_SECRET из базового варианта HS256 больше не требуется. В заголовке JWT записан kid. Для ротации поменяйте JWT_ACTIVE_KID на key1/key2 и перезапустите сервер: оба публичных ключа принимаются валидатором.

## Happy path

```powershell
$url='http://localhost:8080/api/v1'
$pair=Invoke-RestMethod ($url+'/login') -Method Post -ContentType 'application/json' -Body '{"email":"admin@example.com","password":"secret123"}'
$headers=@{Authorization='Bearer '+$pair.access}
Invoke-RestMethod ($url+'/me') -Headers $headers
Invoke-RestMethod ($url+'/admin/stats') -Headers $headers
$next=Invoke-RestMethod ($url+'/refresh') -Method Post -ContentType 'application/json' -Body (@{refresh=$pair.refresh}|ConvertTo-Json)
Invoke-RestMethod ($url+'/me') -Headers @{Authorization='Bearer '+$next.access}
```

Ответ login/refresh содержит access, refresh и token (совместимое имя access из базового примера). Access живёт 15 минут, refresh — 7 дней. Повторный refresh старым токеном даёт 401: его jti заносится в защищённую mutex карту отозванных токенов с exp. Карта находится в памяти текущего процесса; старый access остаётся действителен до exp. Токен refresh нельзя использовать для /me.

User может читать /users/2 (свой sub), но получает 403 для /users/1 и /admin/stats. Admin читает оба профиля. Нет/неверен/просрочен токен — 401, недостаточно прав — 403. Принимается только RS256, проверяются подпись, exp, iss, aud и тип токена. Лимит /login — 5 запросов за 5 минут по IP. Ошибки имеют JSON-формат error/details, логи — метод, путь, код и время без токенов и паролей.

```powershell
go test -v ./...
go vet ./...
go build -o bin/app.exe ./cmd/server
```

Проверены два действующих kid, неверный алгоритм, exp/iss/aud, повторная и конкурентная ротация refresh. Если сервер сообщает об отсутствии ключей — выполнить keygen из корня проекта. Если включился 429 — дождаться окна лимита или перезапустить процесс для нового отдельного прогона.
