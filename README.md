# Pwned Passwords

On February 22, 2018, Troy Hunt released the [V2 update](https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/) to Pwned Passwords.

Pwned Passwords is a service that checks to see if any of your passwords have been leaked in any third-party security breaches. Troy also provided a new API that allows you to lookup a password by using its hash. That means you don't have to send over the password that you want to check.

I created a short Python script that performs the check against the API. It'll hash your password on your local system and check the hash for you against api.pwnedpasswords.com.

As an example, here I'm checking for  `password` as the password. In this example, Over 3 million accounts have been found from third-party breaches using the weak password of `password`.

![alt text](https://github.com/zenone/pwned_passwords/blob/master/images/screenshot-01.png "Example 01")
