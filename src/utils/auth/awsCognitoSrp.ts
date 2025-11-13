import {
  CognitoUserPool,
  CognitoUser,
  AuthenticationDetails,
} from "amazon-cognito-identity-js";
import type { BeforeRequestHook } from "got";

async function login(
  environment: string,
  accessToken: string,
  idToken: string,
  username: string,
  password: string,
  userPoolId: string,
  clientId: string
): Promise<{
  authId: string;
  idToken: string;
  accessToken: string;
}> {

  if (environment === "local" && accessToken && idToken) {
    return {
      authId: username,
      idToken: idToken,
      accessToken: accessToken,
    };
  }

  const poolData = {
    UserPoolId: userPoolId,
    ClientId: clientId,
  };

  const userPool = new CognitoUserPool(poolData);

  const userData = {
    Username: username,
    Pool: userPool,
  };

  const cognitoUser = new CognitoUser(userData);

  const authenticationData = {
    Username: username,
    Password: password,
  };

  const authenticationDetails = new AuthenticationDetails(authenticationData);

  function cognitoLogin() {
    return new Promise<{
      authId: string;
      idToken: string;
      accessToken: string;
    }>((resolve, reject) => {
      cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: (session) => {
          resolve({
            authId: session.getIdToken().getJwtToken(),
            idToken: session.getIdToken().getJwtToken(),
            accessToken: session.getAccessToken().getJwtToken(),
          });
        },
        onFailure: (err) => {
          reject(err);
        },
        // This handler is called if the user's password must be changed
        newPasswordRequired: (userAttributes, requiredAttributes) => {
          // You would typically collect a new password and call:
          // cognitoUser.completeNewPasswordChallenge(newPassword, userAttributes, this);
          reject(new Error("New password required."));
        },
        // Handle other challenges like MFA
        mfaRequired: (codeDeliveryDetails) => {
          // You would typically prompt for MFA code and call:
          // cognitoUser.sendMFACode(mfaCode, this);
          reject(new Error("MFA required."));
        },
      });
    });
  }

  const auth = await cognitoLogin();
  return auth;
}

export async function awsCognitoSrp(
  authorization: string
): Promise<BeforeRequestHook> {
  const [, environment, fallbackAccessToken, fallbackIdToken, username, password, userPoolId, clientId] = authorization.split(/\s+/);

  const { accessToken, idToken } = await login(
    environment,
    fallbackAccessToken,
    fallbackIdToken,
    username,
    password,
    userPoolId,
    clientId
  );

  return async (options) => {
    options.headers = {
      ...options.headers,
      Authorization: `Bearer ${accessToken}`,
      Identity: `${idToken}`
    };
  };
}
