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

import io.sgr.oauth.client.core.OAuthClientConfig;
import io.sgr.social.signin.google.GoogleSignInService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.UUID;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * @author SgrAlpha
 *
 */
public abstract class GooglePlusConnectServlet extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 378774163604342700L;

	private static final Logger LOGGER = LoggerFactory.getLogger(GooglePlusConnectServlet.class.getName());
	
	private GoogleSignInService service;

	@Override
	public void init(ServletConfig conf) throws ServletException {
		this.service = new GoogleSignInService(this.getOAuthClientConfig());
	}

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String secureState = UUID.randomUUID().toString().replaceAll("-", "");
		HttpSession session = req.getSession();
		session.setAttribute(GoogleSignInService.getProviderName() + ".social.secureState", secureState);
		
		String redirectUri = GoogleSignInService.generateServletUrl(req, UrlEndpoints.PATH_CALLBACK);
		
		String accessType = this.getAccessType(req, resp);
		String loginHint = this.getLoginHint(req, resp);
		String scopes = this.getExtraScopes(req, resp);
		String prompt = this.getPrompt(req, resp);
		
		String authorizeUrl = this.service.getAuthorizationUrl(redirectUri, secureState, accessType, loginHint, false, scopes, prompt);
		LOGGER.debug(String.format("[%s] Redirecting guest user to %s", req.getRemoteAddr(), authorizeUrl));
		resp.setHeader("Location", authorizeUrl);
		resp.sendError(HttpServletResponse.SC_MOVED_TEMPORARILY);
	}
	
	/**
	 * @param req
	 * 			The HTTP servlet request
	 * @param resp
	 * 			The HTTP servlet response
	 * @return
	 * 			The scopes
	 */
	protected String getExtraScopes(HttpServletRequest req, HttpServletResponse resp) {
		return req.getParameter("scopes");
	}
	
	/**
	 * @param req
	 * 			The HTTP servlet request
	 * @param resp
	 * 			The HTTP servlet response
	 * @return
	 * 			The access type
	 */
	protected String getAccessType(HttpServletRequest req, HttpServletResponse resp) {
		return req.getParameter("access_type");
	}
	
	/**
	 * @param req
	 * 			The HTTP servlet request
	 * @param resp
	 * 			The HTTP servlet response
	 * @return
	 * 			the prompt setting
	 */
	protected String getPrompt(HttpServletRequest req, HttpServletResponse resp) {
		return req.getParameter("prompt");
	}
	
	/**
	 * @param req
	 * 			The HTTP servlet request
	 * @param resp
	 * 			The HTTP servlet response
	 * @return
	 * 			The login hint
	 */
	protected String getLoginHint(HttpServletRequest req, HttpServletResponse resp) {
		return req.getParameter("login_hint");
	}
	
	protected OAuthClientConfig getOAuthClientConfig() {
		return null;
	}
	
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
