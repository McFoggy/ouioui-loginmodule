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

import java.security.Principal;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

public class OuiOuiGroup implements Group {
    private String name;
    private List<Principal> identities = new ArrayList<Principal>();

    public OuiOuiGroup(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public boolean addMember(Principal user) {
        return identities.add(user);
    }

    public boolean removeMember(Principal user) {
        return identities.remove(user);
    }

    public boolean isMember(Principal member) {
        return identities.contains(member) 
                || identities.stream()
                            .filter(p -> Group.class.isAssignableFrom(p.getClass()))
                            .map(p -> Group.class.cast(p))
                            .anyMatch(g -> g.isMember(member));
    }

    public Enumeration<Principal> members() {
        return Collections.enumeration(identities);
    }
}
