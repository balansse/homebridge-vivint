'use strict';
/* eslint-disable no-console */
// Server side of the plugin's custom config UI (run by homebridge-config-ui-x).
// Copied to dist/homebridge-ui/server.js at build time, hence the ../../lib path.
// @homebridge/plugin-ui-utils 2.x is ESM-only, so it is loaded with a dynamic import.

const { VivintMFA } = require('../../lib/vivint_mfa');

async function main() {
  const { HomebridgePluginUiServer, RequestError } = await import('@homebridge/plugin-ui-utils');

  class PluginUiServer extends HomebridgePluginUiServer {
    constructor() {
      super();
      // Login state for the 2FA round trip of the current UI session
      this.vivintMfa = new VivintMFA();
      this.cookie = '';

      this.onRequest('/send-code', (payload) => this.generateCode(payload));
      this.onRequest('/token', (payload) => this.generateToken(payload));
      this.ready();
    }

    async generateCode({ email, password }) {
      console.log('Logging in to Vivint');
      try {
        this.cookie = await this.vivintMfa.MFALogin(email, password);
        if (this.vivintMfa.using2fa) {
          return { codePrompt: this.vivintMfa.promptFor2fa };
        }
        // If we get here, 2fa was not required.
        return { refreshToken: this.cookie };
      } catch (e) {
        console.error(e.message);
        throw new RequestError(e.message, { message: e.message });
      }
    }

    async generateToken({ code }) {
      console.log('Validating 2FA code');
      try {
        await this.vivintMfa.MFAValidateCode(this.cookie, code);
        return { refreshToken: this.cookie };
      } catch (e) {
        console.error(e.message);
        throw new RequestError('Please check the code and try again', { message: e.message });
      }
    }
  }

  return new PluginUiServer();
}

main().catch((err) => {
  console.error('Failed to start Vivint config UI server:', err && err.message);
  process.exit(1);
});
