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
package io.sgr.social.signin.google.web;

import static io.sgr.oauth.core.utils.Preconditions.isEmptyString;

import io.sgr.oauth.client.core.OAuthClientConfig;
import io.sgr.oauth.core.exceptions.UnrecoverableOAuthException;
import io.sgr.oauth.core.v20.OAuthError;
import io.sgr.social.signin.google.GoogleSignInService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author SgrAlpha
 *
 */
public abstract class GooglePlusDisconnectServlet extends HttpServlet {

	private static final long serialVersionUID = -8496741505555090807L;

	private static final Logger LOGGER = LoggerFactory.getLogger(GooglePlusDisconnectServlet.class.getName());
	
	private GoogleSignInService service;

	@Override
	public void init(ServletConfig conf) throws ServletException {
		this.service = new GoogleSignInService(this.getOAuthClientConfig());
	}

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		LOGGER.debug("Finding token to revoke ...");
		String token = req.getParameter("token");
		if (!isEmptyString(token)) {
			try {
				this.service.revokeToken(token);
			} catch (UnrecoverableOAuthException e) {
				OAuthError err = e.getError();
				LOGGER.warn(String.format("Unable to revoke token %s because [%s]%s", token, err.getName(), err.getErrorDescription()));
			}
		} else {
			LOGGER.debug("No token found in parameter, skipping ...");
		}
		this.postSignOut(req, resp);
	}
	
	protected OAuthClientConfig getOAuthClientConfig() {
		return null;
	}
	
	protected abstract void postSignOut(HttpServletRequest req, HttpServletResponse resp) throws IOException;
	
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
