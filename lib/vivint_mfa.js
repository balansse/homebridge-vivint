const { httpRequest, sessionCookie, describeError } = require('./http.js');

const VIVINT_LOGIN_URL = 'https://www.vivintsky.com/api/login';
const VIVINT_AUTHUSER_URL = 'https://www.vivintsky.com/api/authuser';
const VIVINT_MFA_URL = 'https://www.vivintsky.com/platform-user-api/v0/platformusers/2fa/validate';

// Same headers the previous `request({ json: true })` client sent
const JSON_HEADERS = { accept: 'application/json' };

/**
 * Logs in to Vivint with email/password (optionally followed by a 2FA code) and produces
 * the long-lived refresh token (session cookie) the plugin uses.
 * Never logs credentials, codes or cookies.
 */
class VivintMFA {
    constructor() {
        this.using2fa = false;
        this.promptFor2fa = 'Please enter the code sent to your text/email';
        this.refreshToken = "";
    }

    async MFALogin(email, password) {
        this.using2fa = false;
        this.refreshToken = "";

        //Make request to Login URL to get initial refreshToken.
        let loginResponse;
        try {
            loginResponse = await httpRequest({
                method: "POST",
                url: VIVINT_LOGIN_URL,
                headers: JSON_HEADERS,
                body: {
                    username: email,
                    password: password,
                    "persist_session": true //sets refreshToken timeout to 1 month instead of 20 minutes
                },
            });
        } catch (error) {
            if (error.status === 401 || error.status === 400 || error.status === 403) {
                throw new Error(`Vivint login failed (HTTP ${error.status}). Check your email and password.`, { cause: error });
            }
            throw new Error(`Vivint login failed: ${describeError(error)}`, { cause: error });
        }

        this.refreshToken = sessionCookie(loginResponse) || "";
        if (!this.refreshToken) {
            throw new Error("Failed to retrieve session cookie!");
        }

        //Make request to the Authuser URL to trigger MFA token to send
        const authResponse = await httpRequest({
            method: "GET",
            url: VIVINT_AUTHUSER_URL,
            headers: { ...JSON_HEADERS, Cookie: this.refreshToken },
            throwOnError: false //This allows us to receive a response even if it failed with 401 etc.
        });
        const newSessionCookie = sessionCookie(authResponse);
        if (newSessionCookie) {
            this.refreshToken = newSessionCookie;
        }
        if (authResponse.status === 401) {
            this.using2fa = true;
        } else if (authResponse.status < 200 || authResponse.status >= 300) {
            throw new Error(`Vivint login failed: HTTP ${authResponse.status} from authuser`);
        }
        return this.refreshToken;
    };

    async MFAValidateCode(refreshToken, code) {
        try {
            const response = await httpRequest({
                method: "POST",
                url: VIVINT_MFA_URL,
                headers: { ...JSON_HEADERS, Cookie: refreshToken },
                body: {
                    code: code,
                    "persist_session": true
                },
            });
            return { status: response.status, refreshToken: sessionCookie(response) || refreshToken };
        } catch (error) {
            throw new Error(`2FA code was not accepted: ${describeError(error)}`, { cause: error });
        }
    }
}

exports.VivintMFA = VivintMFA;
