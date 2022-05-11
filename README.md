# Login

Setup är gjort ```express --no-view --git -css sass``` så kör template och klona.

```bash
cd wsp1-login
npm install
mysql -u user -p database < users.sql
```

## Kravspec

En använda ska kunna logga in med en användare på sidan.
En användare ska kunna logga ut från sin användare.
En användare ska kunna registrera ett nytt konto med användarnamn och lösenord.

* Nytt git repo för gruppen med dokumentation
* Databas, tabell för användare
* Node, express med nunjucks, sass
* Routes enligt REST praxis

## Databas

Databasen för användare finns som dump, ```users.sql```.
Importera, lägg till fält vid behov.

```sql
describe users;
+------------+-----------------+------+-----+-------------------+-------------------+
| Field      | Type            | Null | Key | Default           | Extra             |
+------------+-----------------+------+-----+-------------------+-------------------+
| id         | bigint unsigned | NO   | PRI | NULL              | auto_increment    |
| name       | varchar(100)    | NO   |     | NULL              |                   |
| password   | varchar(255)    | NO   |     | NULL              |                   |
| created-at | timestamp       | NO   |     | CURRENT_TIMESTAMP | DEFAULT_GENERATED |
| updated-at | timestamp       | NO   |     | CURRENT_TIMESTAMP | DEFAULT_GENERATED |
+------------+-----------------+------+-----+-------------------+-------------------+
```

För testernas skull finns det en user skapad, test:test.

## Routes

* get register
* post register
* get login
* post login

**requires auth**
* post logout
* get profile

# Arbetsgång

Arbetet är uppdelat i följande huvudmoment, de består i sin tur av ett antal delmoment.

1. Setup
2. Planering
3. Utveckling
4. Koda
5. Extra

Ni kommer att få instruktioner tilldela till er grupp. Varje del kommer att stämmas av med tillhörande tester. När detta är klart så är ni redo att gå vidare till nästa steg. 

## Tester

I det här projektet finns ett antal tester, det är en hjälp för er att komma vidare och för att visa vad ni ska arbeta med. De är även en avstämning för när ni ska gå vidare.

För att köra testerna används https://www.npmjs.com/package/jest
Testerna körs med script som finns i ```package.json```.

För att köra alla tester en gång, använd:
```bash	
npm run test
```

Mer användbar är att starta tester med watch (så de körs automatiskt när ni ändrar i projektet):
```bash
npm run test:watch
```

När jest körs i watch läget så kan ni styra hur det ska köra testerna.
Ni kan till exempel välja att filtrera vilka tester som ska köras. För att göra det så väljer ni ```p``` och skriver testets namn. För det här projektet finns följande tester:
* 1-server
* 2-login
* 3-auth
* 4-register

Ni kan även köra dem med de script som finns i package.json.
```bash	
npm run test:1
npm run test:2
npm run test:3
npm run test:4
```