import {
  AuthenticationDetails,
  CognitoUser,
  CognitoUserPool,
  CognitoUserSession,
} from "amazon-cognito-identity-js";
import type { BeforeRequestHook } from "got";

interface CognitoAuthParams {
  environment: string;
  accessToken?: string;
  idToken?: string;
  username: string;
  password: string;
  userPoolId: string;
  clientId: string;
}

interface AuthTokens {
  idToken: string;
  accessToken: string;
}

async function login(params: CognitoAuthParams): Promise<AuthTokens> {
  const {
    environment,
    accessToken,
    idToken,
    username,
    password,
    userPoolId,
    clientId,
  } = params;

  // Validate required parameters
  if (!username || !password) {
    throw new Error("AWS Cognito: username and password are required");
  }

  if (!userPoolId || !clientId) {
    throw new Error("AWS Cognito: userPoolId and clientId are required");
  }

  // Local environment bypass
  if (environment === "local" && accessToken && idToken) {
    return {
      idToken,
      accessToken,
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

  try {
    const session = await new Promise<CognitoUserSession>((resolve, reject) => {
      cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: (session) => {
          resolve(session);
        },
        onFailure: (err) => {
          reject(new Error(`AWS Cognito authentication failed: ${err.message || err}`));
        },
        // This handler is called if the user's password must be changed
        newPasswordRequired: () => {
          // You would typically collect a new password and call:
          // cognitoUser.completeNewPasswordChallenge(newPassword, userAttributes, this);
          reject(new Error("AWS Cognito: new password required for this user"));
        },
        // Handle other challenges like MFA
        mfaRequired: () => {
          // You would typically prompt for MFA code and call:
          // cognitoUser.sendMFACode(mfaCode, this);
          reject(new Error("AWS Cognito: MFA verification required"));
        },
      });
    });

    return {
      idToken: session.getIdToken().getJwtToken(),
      accessToken: session.getAccessToken().getJwtToken(),
    };
  } catch (error) {
    // Re-throw with context if it's not already our error
    if (error instanceof Error && error.message.startsWith("AWS Cognito")) {
      throw error;
    }
    throw new Error(`AWS Cognito authentication error: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export async function awsCognitoSrp(
  authorization: string
): Promise<BeforeRequestHook> {
  // Parse authorization string
  const parts = authorization.split(/\s+/);

  if (parts.length < 8) {
    throw new Error(
      "Invalid AWS Cognito SRP authorization format. Expected: 'awsCognitoSrp <environment> <accessToken> <idToken> <username> <password> <userPoolId> <clientId>'"
    );
  }

  const [
    ,
    environment,
    fallbackAccessToken,
    fallbackIdToken,
    username,
    password,
    userPoolId,
    clientId,
  ] = parts;

  const { accessToken, idToken } = await login({
    environment,
    accessToken: fallbackAccessToken,
    idToken: fallbackIdToken,
    username,
    password,
    userPoolId,
    clientId,
  });

  return async (options) => {
    options.headers = {
      ...options.headers,
      Authorization: `Bearer ${accessToken}`,
      Identity: idToken,
    };
  };
}
