# About
Authentication libraries are typically very messy, usually they're terrible to start off with, too cramped and don't solve a problem enough to be worth using. Most developers resort to session keys / bearer tokens because it's the easiest. This library aims to change that by making public / private key signing authentication easier than session / bearer tokens.

**Why should I be using public/private key signing for authentication?**
Session keys / bearer tokens are weak because if someone intercepts them, they can use them. With public / private key signing and correct implementation, if someone were to intercept your request, they would only to be able to resend the request you just signed (and that can be stopped with nonces and signing) and can't use the authentication for whatever they want. With session / bearer tokens, if someone intercepts your request, they can take that token and use it to the full extent it's authorized.

If your database is leaked, with session keys / bearer tokens, it comes down to your hashing methods and handling of that data in your database, including if someone had gotten into a webserver/load-balancer and started collecting tokens. With public / private key signing, you're only storing public-keys on your end and they're called "public-keys" for a reason, because it doesn't matter if they're leaked.

# Versions
[NPM](https://github.com/oracularhades/authenticator/tree/main/npm)
