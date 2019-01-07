/*
 * Copyright 2017-2019 SgrAlpha
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package io.sgr.social.signin.google;

import static io.sgr.oauth.core.utils.Preconditions.isEmptyString;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import io.sgr.oauth.client.core.OAuthClientConfig;
import io.sgr.oauth.client.core.OAuthHttpClient;
import io.sgr.oauth.client.googlehttp.OAuthGoogleHttpClient;
import io.sgr.oauth.core.OAuthCredential;
import io.sgr.oauth.core.exceptions.OAuthException;
import io.sgr.oauth.core.exceptions.UnrecoverableOAuthException;
import io.sgr.oauth.core.utils.Preconditions;
import io.sgr.oauth.core.v20.OAuthError;
import io.sgr.oauth.core.v20.ParameterStyle;
import io.sgr.oauth.core.v20.ResponseType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;

/**
 * @author SgrAlpha
 *
 */
public final class GoogleSignInService implements Closeable {

	public static final String PROVIDER_NAME = "google";

	private static final Logger LOGGER = LoggerFactory.getLogger(GoogleSignInService.class.getName());

	private OAuthHttpClient oauthClient;

	public GoogleSignInService() {
		this(null);
	}

	public GoogleSignInService(OAuthClientConfig clientConfig) {
		OAuthClientConfig config = clientConfig;
		if (config == null) {
			LOGGER.debug("No OAuth client config specifed, scanning classpath ...");
			try {
				config = OAuthClientConfig.readFromClasspath("social/google/client.json");
			} catch (Throwable e) {
				throw new RuntimeException("Unable to read OAuth client config from classpath: social/google/client.json", e);
			}
		}
		try {
			this.oauthClient = OAuthGoogleHttpClient.newInstance(config, getDefaultHttpTransport(), null);
		} catch (Throwable e) {
			throw new RuntimeException("Failed to init " + OAuthGoogleHttpClient.class.getSimpleName(), e);
		}
	}

	/**
	 * @param redirectUri
	 * 			The redirect URL to receive authorization code.
	 * @param secureState
	 * 			The state
	 * @param accessType
	 * 			Indicates whether your application needs to access a Google API when the user is not present at the browser.
	 * 			This parameter defaults to online. If your application needs to refresh access tokens when the user is not present at the browser, then use offline.
	 *			This will result in your application obtaining a refresh token the first time your application exchanges an authorization code for a user.
	 * @param loginHint
	 * 			Email address or sub identifier.
	 * 			When your application knows which user it is trying to authenticate, it can provide this parameter as a hint to the Authentication Server.
	 * 			Passing this hint will either pre-fill the email box on the sign-in form or select the proper multi-login session, thereby simplifying the login flow.
	 * @param includeGrantedScopes
	 * 			If this is provided with the value true, and the authorization request is granted, the authorization will include any previous authorizations granted to this user/application combination for other scopes.
	 * @param extraScopes
	 * 			Space-delimited list of extra scopes beside of "profile email" for the OAuth request
	 * @param prompts
	 * 			Space-delimited, case-sensitive list of prompts to present the user. If you don't specify this parameter, the user will be prompted only the first time your app requests access.
	 * @return
	 * 			The authorization URL
	 */
	public final String getAuthorizationUrl(String redirectUri, String secureState, String accessType, String loginHint, Boolean includeGrantedScopes, String extraScopes, String prompts) {
		String scope = "profile email";
		if (!isEmptyString(extraScopes)) {
			scope = scope + " " + extraScopes;
		}

		Map<String, String> props = new HashMap<>();
		if (!isEmptyString(accessType)) {
			props.put("access_type", accessType);
		}
		if (!isEmptyString(loginHint)) {
			props.put("login_hint", loginHint);
		}
		if (includeGrantedScopes != null) {
			props.put("include_granted_scopes", includeGrantedScopes.toString());
		}
		if (prompts != null) {
			props.put("prompt", prompts);
		}

		try {
			return this.oauthClient.getAuthorizeURL(ResponseType.CODE, redirectUri , secureState, scope , props);
		} catch (OAuthException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * @param code
	 * 			The authorization code
	 * @param redirectUri
	 * 			The redirect URI to receive access token
	 * @return
	 * 			The OAuth credential
	 * @throws UnrecoverableOAuthException 
	 * 			Exception when retrieving access token
	 */
	public final OAuthCredential getAccessToken(String code, String redirectUri) throws UnrecoverableOAuthException {
		int interval = 1;
		int retryCnt = 0;
		try {
			while (!Thread.interrupted()) {
				if (interval > 30) {
					interval = 30;
				}
				if (retryCnt >= 30) {
					LOGGER.warn("Maximum retry exceeded, unable to get access token");
					break;
				}
				try {
					return this.oauthClient.getAccessTokenByAuthorizationCode(ParameterStyle.BODY, code, redirectUri);
				} catch (UnrecoverableOAuthException e) {
					throw e;
				} catch (OAuthException e) {
					OAuthError err = e.getError();
					LOGGER.warn(String.format("Unable to get access token because of [%s]%s, retry after %d second(s).", err.getName(), err.getErrorDescription(), interval));
				}
				TimeUnit.SECONDS.sleep(interval++);
				retryCnt++;
			}
		} catch (InterruptedException ie) {
			LOGGER.info("Cancelling ...");
			Thread.currentThread().interrupt();
		}
		return null;
	}

	public final GoogleAccount parseUserIdentity(OAuthCredential credential) {
		if (credential != null && credential.getExtraParams() != null && !credential.getExtraParams().isEmpty() && credential.getExtraParams().get("id_token") != null) {
			String idToken = credential.getExtraParams().get("id_token").toString();
			return parseUserIdentity(idToken);
		}
		return null;
	}

	public final GoogleAccount parseUserIdentity(String idToken) {
		if (isEmptyString(idToken)) {
			return null;
		}
		LOGGER.debug(String.format("Found ID token %s, verifying user's identity ...", idToken));
		return parseGoogleAccountFromIdToken(this.oauthClient.getOAuthClientConfig().clientId, idToken);
	}

	public final GoogleAccount getUserIdentity(OAuthCredential credential) throws UnrecoverableOAuthException {
		if (credential == null) {
			throw new UnrecoverableOAuthException(new OAuthError("blank_credential", "No credential found."));
		}
		GoogleAccount account = this.parseUserIdentity(credential);
		if (account != null) {
			return account;
		}

		LOGGER.debug("Try refresh the access token ...");
		if (isEmptyString(credential.getRefreshToken())) {
			throw new UnrecoverableOAuthException(new OAuthError("blank_token", "No access token or refresh token, even ID token found."));
		}
		try {
			credential = this.refreshToken(credential.getRefreshToken());
			account = this.parseUserIdentity(credential);
		} catch (UnrecoverableOAuthException e) {
			throw e;
		}
		return account;
	}

	/**
	 * @param refreshToken
	 * 				The refresh token used to fresh new OAuth credential
	 * @return
	 * 				The OAuth credential
	 * @throws UnrecoverableOAuthException 
	 * 				Exception when refreshing OAuth credential
	 */
	public final OAuthCredential refreshToken(String refreshToken) throws UnrecoverableOAuthException {
		if (isEmptyString(refreshToken)) {
			throw new UnrecoverableOAuthException(new OAuthError("missing_refresh_token", "Cannot refresh access token without refresh token"));
		}
		int interval = 1;
		int retryCnt = 0;
		try {
			while (!Thread.interrupted()) {
				if (interval > 30) {
					interval = 30;
				}
				if (retryCnt >= 30) {
					LOGGER.warn("Maximium retry exceeded, unable to refresh token");
					break;
				}
				LOGGER.debug(String.format("Refreshing access token with refresh token %s.", refreshToken));
				try {
					return this.oauthClient.refreshToken(ParameterStyle.BODY, refreshToken);
				} catch (UnrecoverableOAuthException e) {
					throw e;
				} catch (OAuthException e) {
					OAuthError err = e.getError();
					LOGGER.warn(String.format("Unable to refresh access token because of [%s]%s, retry after %d second(s).", err.getName(), err.getErrorDescription(), interval));
				}
				TimeUnit.SECONDS.sleep(interval++);
				retryCnt++;
			}
		} catch (InterruptedException ie) {
			LOGGER.info("Cancelling ...");
			Thread.currentThread().interrupt();
		}
		return null;
	}

	/**
	 * @param token
	 * 			The OAuth token to revoke
	 * @throws UnrecoverableOAuthException 
	 * 			Exception when revoking OAuth token
	 */
	public final void revokeToken(String token) throws UnrecoverableOAuthException {
		if (isEmptyString(token)) {
			LOGGER.debug("Null or blank OAuth token, nothing to revoke.");
			return;
		}
		int interval = 1;
		int retryCnt = 0;
		try {
			while (!Thread.interrupted()) {
				if (interval > 30) {
					interval = 30;
				}
				if (retryCnt >= 30) {
					LOGGER.warn("Maximium retry exceeded, unable to revoke token.");
					break;
				}
				LOGGER.debug(String.format("Revoking token %s.", token));
				try {
					this.oauthClient.revokeToken(token);
					break;
				} catch (UnrecoverableOAuthException e) {
					throw e;
				} catch (OAuthException e) {
					OAuthError err = e.getError();
					LOGGER.warn(String.format("Unable to revoke token because of [%s]%s, retry after %d second(s).", err.getName(), err.getErrorDescription(), interval));
				}
				TimeUnit.SECONDS.sleep(interval++);
				retryCnt++;
			}
		} catch (InterruptedException ie) {
			LOGGER.info("Cancelling ...");
			Thread.currentThread().interrupt();
		}
	}

	/**
	 * @return
	 * 			The provider name of this OAuth server
	 */
	public static String getProviderName() {
		return PROVIDER_NAME;
	}

	public static String generateServletUrl(HttpServletRequest request, String relativePath) {
		String scheme = request.getScheme().toLowerCase();
		String serverName = request.getServerName();
		int serverPort = request.getServerPort();
		String contextPath = request.getContextPath();
		StringBuilder url =  new StringBuilder();
		url.append(scheme).append("://").append(serverName);
		if (("http".equals(scheme) && serverPort != 80) || ("https".equals(scheme) && serverPort != 443)) {
			url.append(":").append(serverPort);
		}
		url.append(contextPath);
		if (!isEmptyString(relativePath)) {
			url.append(relativePath);
		}
		return url.toString();
	}

	private static GoogleAccount parseGoogleAccountFromIdToken(String clientId, String idTokenString) {
		Preconditions.notEmptyString(clientId, "OAuth client ID should be provided.");
		Preconditions.notEmptyString(idTokenString, "IdToken should be provided.");
	
		GoogleIdTokenVerifier oldVerifier = new GoogleIdTokenVerifier.Builder(getDefaultHttpTransport(), getDefaultJsonFactory())
				.setAudience(Collections.singletonList(clientId))
				// For Android Play Services older than 8.3 and web client
				.setIssuer("accounts.google.com")
				.build();
	
		GoogleIdTokenVerifier newVerifier = new GoogleIdTokenVerifier.Builder(getDefaultHttpTransport(), getDefaultJsonFactory())
				.setAudience(Collections.singletonList(clientId))
				// For Android Play Services newer than 8.3
				.setIssuer("https://accounts.google.com")
				.build();
	
		GoogleIdToken idToken;
		try {
			idToken = oldVerifier.verify(idTokenString);
			if (idToken == null) {
				idToken = newVerifier.verify(idTokenString);
			}
		} catch (Exception e) {
			LOGGER.error(e.getMessage(), e);
			return null;
		}
		if (idToken == null) {
			LOGGER.warn(String.format("Invalid or expired Google ID token: %s", idTokenString));
			return null;
		}
	
		Payload payload = idToken.getPayload();
		for (Entry<String, Object> entry : payload.entrySet()) {
			LOGGER.trace(String.format("%s=%s", entry.getKey(), entry.getValue()));
		}
	
		return idTokenPayloadToGoogleAccount(payload);
	}

	private static GoogleAccount idTokenPayloadToGoogleAccount(Payload payload) {
		String id = payload.getSubject();
		if (isEmptyString(id)) {
			LOGGER.error("No subject ID found in ID token payload, please check your scope settings.");
			return null;
		}
	
		String email = payload.getEmail();
		if (isEmptyString(email)) {
			LOGGER.error("No email found in ID token payload, please check your scope settings.");
			return null;
		}
		//		boolean emailVerified = Boolean.valueOf(payload.getEmailVerified());
		//		LOGGER.debug(String.format("email: %s (verified: %s)", email, emailVerified));
		String name = (String) payload.get("name");
		if (isEmptyString(name)) {
			name = "John/Jane Doe";
		}
		//		LOGGER.debug(String.format("name: %s", name));
		String pictureUrl = (String) payload.get("picture");
		if (isEmptyString(pictureUrl)) {
			pictureUrl = "https://ssl.gstatic.com/accounts/ui/avatar_1x.png";
		}
		//		LOGGER.debug(String.format("pictureUrl: %s", pictureUrl));
		//		String locale = (String) payload.get("locale");
		//		LOGGER.debug(String.format("locale: %s", locale));
		//		String familyName = (String) payload.get("family_name");
		//		String givenName = (String) payload.get("given_name");
		//		LOGGER.debug(String.format("Full Name: %s,%s", familyName, givenName));
	
		return new GoogleAccount(id, email, name, pictureUrl);
	}

	/**
	 * @return
	 * 				Default HTTP transport
	 */
	private static HttpTransport getDefaultHttpTransport() {
		return new NetHttpTransport();
	}

	/**
	 * @return
	 * 				Default Json factory
	 */
	private static JsonFactory getDefaultJsonFactory() {
		return JacksonFactory.getDefaultInstance();
	}

	/* (non-Javadoc)
	 * @see java.io.Closeable#close()
	 */
	@Override
	public void close() throws IOException {
		this.oauthClient.close();
	}

}
