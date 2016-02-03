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

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.util.Collections;

import org.junit.Test;

public class OuiOuiPrincipalGroupTest {
    @Test
    public void name_is_retrieved_correctly_in_principal() {
        String name = "Lucas";
        
        OuiOuiPrincipal p = new OuiOuiPrincipal(name);
        
        assertThat(p, notNullValue());
        assertThat("retrieved principal name is wrong", p.getName(), is(name));
    }
    
    @Test
    public void name_is_retrieved_correctly_in_group() {
        String name = "Anais";
        
        OuiOuiGroup p = new OuiOuiGroup(name);
        
        assertThat(p, notNullValue());
        assertThat("retrieved group name is wrong", p.getName(), is(name));
    }
    
    @Test
    public void an_assigned_principal_is_retrieved_in_group() {
        OuiOuiGroup g = new OuiOuiGroup("g");
        OuiOuiPrincipal p = new OuiOuiPrincipal("p");
        
        g.addMember(p);
        
        assertTrue("expected principal is not a member of group", g.isMember(p));
        assertThat("members enumeration of group is null", g.members(), notNullValue());
        assertThat("members enumeration does not contain the principal", Collections.list(g.members()), hasItem(p));
    }
    
    @Test
    public void a_principal_in_sub_group_is_member_of_outer_group() {
        OuiOuiGroup main = new OuiOuiGroup("main");
        OuiOuiGroup sub = new OuiOuiGroup("sub");
        OuiOuiPrincipal p = new OuiOuiPrincipal("p");
        
        sub.addMember(p);
        main.addMember(sub);
        
        assertTrue("principal not found in outer group", main.isMember(p));
    }
}
