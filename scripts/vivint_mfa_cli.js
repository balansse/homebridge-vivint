#!/usr/bin/env node
// Interactive helper that logs in to Vivint (with 2FA if enabled) and prints the refresh
// token to put in the plugin config. Run with `npm run mfa`.

const readline = require('readline');
const { VivintMFA } = require('../lib/vivint_mfa');

function askQuestion(query, { hidden = false } = {}) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: true,
  });

  if (hidden) {
    // Echo '*' instead of the typed characters
    rl._writeToOutput = function (text) {
      if (text.includes(query)) rl.output.write(query);
      else if (text === '\r\n' || text === '\n') rl.output.write(text);
      else rl.output.write('*'.repeat(text.length));
    };
  }

  return new Promise((resolve) => rl.question(query, (ans) => {
    rl.close();
    if (hidden) process.stdout.write('\n');
    resolve(ans.trim());
  }));
}

const run = async () => {
  const email = await askQuestion('Please enter your Vivint login email: ');
  const password = await askQuestion('Please enter your Vivint login password: ', { hidden: true });

  const mfa = new VivintMFA();
  const refreshToken = await mfa.MFALogin(email, password);

  if (mfa.using2fa) {
    const code = await askQuestion('Please enter the MFA code from your authenticator app or the one you received via sms or email: ');
    await mfa.MFAValidateCode(refreshToken, code);
  } else {
    console.log('MFA is not needed for this account.');
  }

  console.log('\nPlease use refreshToken: ' + refreshToken + '\n');
};

run().catch((error) => {
  console.error('Error: ' + error.message);
  process.exitCode = 1;
});
