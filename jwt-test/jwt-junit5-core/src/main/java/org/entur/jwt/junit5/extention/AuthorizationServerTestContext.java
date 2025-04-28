package org.entur.jwt.junit5.extention;

import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;

public class AuthorizationServerTestContext {

    private Map<Annotation, List<AuthorizationServerImplementation>> authorizationServers;

    public AuthorizationServerTestContext(List<AuthorizationServerImplementation> list) {
        super();

        Map<Annotation, List<AuthorizationServerImplementation>> values = new HashMap<>();
        for (AuthorizationServerImplementation item : list) {
            List<AuthorizationServerImplementation> itemList = new ArrayList<>();
            itemList.add(item);
            values.put(item.getAnnotation(), itemList);
        }

        this.authorizationServers = values;
    }

    public List<AuthorizationServerImplementation> getAuthorizationServers(AuthorizationServerImplementation impl) {
        return authorizationServers.get(impl.getAnnotation());
    }
    
    public void add(AuthorizationServerImplementation impl) {
        List<AuthorizationServerImplementation> list = authorizationServers.get(impl.getAnnotation());
        if(list == null) {
            list = new ArrayList<>();
            
            authorizationServers.put(impl.getAnnotation(), list);
        }
        
        if(!list.contains(impl)) { // i.e. instance check, since keys are connected to instances
            list.add(impl);
        }
    }
  
    public Set<String> getServerNames() {
        Set<String> set = new HashSet<>();
        for (Entry<Annotation, List<AuthorizationServerImplementation>> entry : authorizationServers.entrySet()) {
            set.add(entry.getValue().get(0).getId());
        }
        return set;
    }
   

}
