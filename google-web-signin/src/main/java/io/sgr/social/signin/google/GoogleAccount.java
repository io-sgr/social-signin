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

import com.fasterxml.jackson.annotation.JsonInclude;
import io.sgr.oauth.core.utils.Preconditions;

/**
 * @author SgrAlpha
 *
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GoogleAccount {
	
	private final String id;
	private final String email;
	private final String displayName;
	private final String avatarUrl;
	
	/**
	 * @param id
	 * 			The user id from social network, could be a serial number
	 * @param email
	 * 			The user's email from social network
	 * @param displayName
	 * 			The display name of the user 
	 * @param avatarUrl
	 * 			The profile image URL of the user
	 */
	public GoogleAccount(String id, String email, String displayName, String avatarUrl) {
		Preconditions.notEmptyString(id, "ID should be provided");
		this.id = id;
		this.email = email;
		this.displayName = displayName;
		this.avatarUrl = avatarUrl;
	}
	
	public String getId() {
		return this.id;
	}

	public String getEmail() {
		return this.email;
	}

	public String getDisplayName() {
		return this.displayName;
	}

	public String getAvatarUrl() {
		return this.avatarUrl;
	}

}
