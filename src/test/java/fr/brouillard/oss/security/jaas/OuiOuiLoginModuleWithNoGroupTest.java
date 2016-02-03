/**
 * Copyright (C) 2015 McFoggy [https://github.com/McFoggy/ouioui-loginmodule] (matthieu@brouillard.fr)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package fr.brouillard.oss.security.jaas;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import org.junit.Before;
import org.junit.Test;

public class OuiOuiLoginModuleWithNoGroupTest {
    private OuiOuiLoginModule lm;
    private Map<String, String> sharedState;
    private Map<String, String> options;
    private String loginName = "lucas";
    private String loginPassword = "just4fun";
    private Subject subject;
    
    @Before
    public void init() {
        lm = new OuiOuiLoginModule();
        sharedState = new HashMap<>();
        options = new HashMap<>();
        subject = new Subject();
    }
    
    @Test
    public void login_succeeds_when_name_only_is_provided() throws LoginException {
        lm.initialize(subject, new ExplicitCallbackHandler(loginName, null), sharedState, options);
        assertTrue("authentication must have succeeded", lm.login());
        
        assertThat("login entry must have been set in shared state", sharedState.get("javax.security.auth.login.name"), is(loginName));
        assertTrue("password entry must exist in shared state", sharedState.containsKey("javax.security.auth.login.password"));
    }
    
    @Test
    public void login_succeeds_when_name_and_password_are_provided() throws LoginException {
        lm.initialize(subject, new ExplicitCallbackHandler(loginName, loginPassword), sharedState, options);
        
        assertTrue("authentication must have succeeded", lm.login());
        
        assertThat("login entry must have been set in shared state", sharedState.get("javax.security.auth.login.name"), is(loginName));
        assertThat("password entry must have been set in shared state", sharedState.get("javax.security.auth.login.password"), is(loginPassword));
    }
    
    @Test
    public void subject_is_filled_with_principal() throws LoginException {
        lm.initialize(subject, new ExplicitCallbackHandler(loginName, loginPassword), sharedState, options);
        lm.login();
        
        assertTrue("commit must succeed", lm.commit());
        
        assertTrue("subject must contain a principal with given login", subject.getPrincipals().stream().anyMatch(p -> loginName.equals(p.getName())));
    }
}
