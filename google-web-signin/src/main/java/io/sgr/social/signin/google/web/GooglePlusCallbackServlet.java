/*
 * Copyright 2017-2018 SgrAlpha
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
package io.sgr.social.signin.google.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.sgr.oauth.client.core.OAuthClientConfig;
import io.sgr.oauth.core.OAuthCredential;
import io.sgr.oauth.core.exceptions.UnrecoverableOAuthException;
import io.sgr.oauth.core.utils.Preconditions;
import io.sgr.oauth.core.v20.OAuth20;
import io.sgr.social.signin.google.GoogleAccount;
import io.sgr.social.signin.google.GoogleSignInService;

/**
 * @author SgrAlpha
 *
 */
public abstract class GooglePlusCallbackServlet extends HttpServlet {

	private static final long serialVersionUID = -6572277840823073716L;

	private static final Logger LOGGER = LoggerFactory.getLogger(GooglePlusCallbackServlet.class.getName());
	
	private GoogleSignInService service;

	@Override
	public void init() throws ServletException {
		this.service = new GoogleSignInService(this.getOAuthClientConfig());
	}

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String error = req.getParameter("error");
		if (!Preconditions.isEmptyString(error)) {
			this.onError(error, req, resp);
			return;
		}
		
		String secureState = req.getParameter(OAuth20.OAUTH_STATE);
		if (Preconditions.isEmptyString(secureState)) {
			this.onError("missing_secure_state", req, resp);
			return;
		}
		HttpSession session = req.getSession();
		Object secureStateObj = session.getAttribute(GoogleSignInService.getProviderName() + ".social.secureState");
		if (secureStateObj == null || !secureStateObj.equals(secureState)) {
			this.onError("secure_state_mismatch", req, resp);
			return;
		}
		
		String code = req.getParameter(OAuth20.OAUTH_CODE);
		String redirectUri = GoogleSignInService.generateServletUrl(req, UrlEndpoints.PATH_CALLBACK);
		
		LOGGER.debug(String.format("[%s] Retrieving access token with authorization code %s", req.getRemoteAddr(), code));
		try {
			OAuthCredential credential = this.service.getAccessToken(code, redirectUri);
			LOGGER.debug(String.format("[%s] Access token received %s", req.getRemoteAddr(), credential));
			GoogleAccount account = this.service.getUserIdentity(credential);
			LOGGER.debug(String.format("[%s] Found valid account info: %s", req.getRemoteAddr(), account));
			this.onSuccess(credential, account, req, resp);
		} catch (UnrecoverableOAuthException e) {
			this.onError(e.getError().getName(), req, resp);
		}
	}
	
	protected OAuthClientConfig getOAuthClientConfig() {
		return null;
	}
	
	protected abstract void onSuccess(OAuthCredential credential, GoogleAccount account, HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException;
	protected abstract void onError(String error, HttpServletRequest req, HttpServletResponse resp) throws IOException;
	
	@Override
	public void destroy() {
		super.destroy();
		try {
			if (this.service != null) {
				this.service.close();
			}
		} catch (IOException e) {
			LOGGER.error(e.getMessage(), e);
		}
	}
	
}
