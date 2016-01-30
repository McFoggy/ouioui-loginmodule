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

import java.io.IOException;
import java.security.Principal;
import java.util.Arrays;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OuiOuiLoginModule implements LoginModule {
    private Map<String, String> options;
    private CallbackHandler callbackHandler;
    private Map<String, String> sharedState;
    private String name;
    private String password;
    private Subject subject;
    
    private final static Logger LOG = LoggerFactory.getLogger(OuiOuiLoginModule.class);

    public static final String JAVAX_SECURITY_AUTH_LOGIN_NAME = "javax.security.auth.login.name";
    public static final String JAVAX_SECURITY_AUTH_LOGIN_PASSWORD = "javax.security.auth.login.password";

    public static final String OPTION_ROLES = "roles";
    
    private OuiOuiPrincipal principal;
    private OuiOuiGroup rolesGroup;
    
    public OuiOuiLoginModule() {
    }
    
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = (Map<String, String>) sharedState;
        this.options = (Map<String, String>) options;
    }

    public boolean login() throws LoginException {
        readCredentials();

        // Our only constraint is that we have a user
        if (name == null) {
            throw new LoginException("no username provided cannot authenticate");
        }

        // We have a user, as a OuiOui/Noddy we just accept it
        LOG.debug("user: " + name + " login");
        
        // we enable password-stacking for other modules
        sharedState.put(JAVAX_SECURITY_AUTH_LOGIN_NAME, name);
        sharedState.put(JAVAX_SECURITY_AUTH_LOGIN_PASSWORD, password);
        
        return true;
    }

    
    boolean readCredentials() throws LoginException {
        Callback[] callbacks = handleCallbacks();
        extractDataFromCallbacks(callbacks);
        return true;
    }
    
    public boolean commit() throws LoginException {
        boolean commit = true;
        
        // First we authenticate the user
        principal = new OuiOuiPrincipal(name);
        commit &= subject.getPrincipals().add(principal);
        
        // Then we try to authorize him with roles
        String rolesAsString = options.get(OPTION_ROLES);
        if (rolesAsString == null) {
        	LOG.trace("missing option {} in {} configuration", OPTION_ROLES, OuiOuiLoginModule.class);
        } else if (rolesAsString.trim().length() == 0) {
        	LOG.trace("no role to assign to user: {}", name);
        } else {
        	rolesGroup = new OuiOuiGroup("Roles");
        	String[] roles = rolesAsString.split(",\\s*");
        	for (String roleName : roles) {
        		Principal role = new OuiOuiPrincipal(roleName);
        		LOG.debug("adding role {}", roleName);
        		rolesGroup.addMember(role);
        	}
        	
        	LOG.debug("user {} was assigned roles: {}", rolesAsString);
        	commit &= subject.getPrincipals().add(rolesGroup);
        }
        
        return commit;
    }

    public boolean abort() throws LoginException {
        return false;
    }

    public boolean logout() throws LoginException {
    	// Let's secure the logout, not the moment to throw some NPE
    	if (subject != null) {
    		if (principal != null) {
    			subject.getPrincipals().remove(principal);
    		}
    		if (rolesGroup != null) {
    			subject.getPrincipals().remove(rolesGroup);
    		}
    	}
        return true;
    }

    private Callback[] handleCallbacks() throws LoginException {
        Callback[] callbacks = supportedCallbacks();
        try {
            callbackHandler.handle(callbacks);
        } catch (IOException e) {
            LoginException le = new LoginException("IO exception occurred while handling callbacks");
            le.initCause(e);
            throw le;
        } catch (UnsupportedCallbackException e) {
            Callback callback = e.getCallback();
            LOG.debug("Callback '{}' not supported", callback != null ? callback.getClass().getName() : "null");
        }
        return callbacks;
    }
    
    protected final Callback[] supportedCallbacks() {
        Callback[] callbacks = new Callback[] {
                new NameCallback("Name:"),
                new PasswordCallback("Password:", false)
        };
        return callbacks;
    }
    
    void extractDataFromCallbacks(Callback[] callbacks) {
        for (Callback callback : callbacks) {

            if (callback instanceof NameCallback) {
                NameCallback nameCallback = (NameCallback) callback;
                this.name = nameCallback.getName();

            } else if (callback instanceof PasswordCallback) {
                PasswordCallback passwordCallback = (PasswordCallback) callback;
                char[] pw = passwordCallback.getPassword();
                if (pw != null) {
                    password = new String(pw);
                } else {
                    password = null;
                }
            }
        }
    }
}
