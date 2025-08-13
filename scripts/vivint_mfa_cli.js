#!/usr/bin/env node

const request = require("request-promise-native")
const readline = require('readline');

const VIVINT_LOGIN_URL = 'https://www.vivintsky.com/api/login';
const VIVINT_AUTHUSER_URL = 'https://www.vivintsky.com/api/authuser';
const VIVINT_MFA_URL = 'https://www.vivintsky.com/platform-user-api/v0/platformusers/2fa/validate';

const run = async () => {

  let refreshToken = "";
  let isMfa = false;
  let email = await askQuestion("Please enter your Vivint login email: ");
  let password = await askQuestion("Please enter your Vivint login password: ");


  try {
    response = await request({
      method: "POST",
      url: VIVINT_LOGIN_URL,
      body: {
        username: email,
        password: password,
        "persist_session": true
      },
      json: true,
      resolveWithFullResponse: true
    });
    console.log("Response = " + JSON.stringify(response, null, 4));
    const loginSetCookies = (response.headers && response.headers["set-cookie"]) || [];
    refreshToken = loginSetCookies.filter((cookie) => cookie.startsWith("s="))[0];
    if (!refreshToken) {
        throw new Error("Failed to retrieve session cookie!");
    }
    refreshToken = refreshToken.split(";")[0];
  } catch (error) {
    console.error(error);
  }

  //Next is the Auth User Data attempt, this should trigger MFA code to be sent.
  try {
    response = await request({
      method: "GET",
      url: VIVINT_AUTHUSER_URL,
      headers: { Cookie: refreshToken },
      json: true,
      resolveWithFullResponse: true,
      simple: false //This allows us to receive a response even if it failed with 401 etc
    });
    console.log("Response = " + JSON.stringify(response, null, 4));
    const authSetCookies = (response.headers && response.headers["set-cookie"]) || [];
    let newRefreshToken = authSetCookies.filter((cookie) => cookie.startsWith("s="))[0];
    if (newRefreshToken) {
      refreshToken = newRefreshToken.split(";")[0];
    }
    if (response.statusCode === 401) {
      isMfa = true;
    } else {
      console.log("Status code was " + response.statusCode + ".  MFA is not needed.");
      console.log("Please use refreshToken: " + refreshToken);
    }
  } catch (error) {
    console.error(error);
  }
  //if response was error 401, we are going to ask user to type in the MFA code they received.
  if (isMfa) {
    const code = await askQuestion("Please enter the MFA code from your authenticator app or the one you received via sms or email : ");
    try {
      response = await request({
        method: "POST",
        url: VIVINT_MFA_URL,
        headers: { Cookie: refreshToken },
        body: {
          code: code,
          "persist_session": true
        },
        json: true,
        resolveWithFullResponse: true,

      });
      console.log("\n" + "Please use refreshToken: " + refreshToken + "\n");
    } catch (error) {
      console.error("Wrong Code Entered. " + error);
    }
  }
};

function askQuestion(query) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise(resolve => rl.question(query, ans => {
    rl.close();
    resolve(ans);
  }))
}

try {
  run();
} catch (error) {
  console.log(error.message);
}
