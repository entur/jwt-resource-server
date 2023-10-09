package org.entur.jwt.spring.properties;

import org.springframework.http.HttpMethod;

import java.util.ArrayList;
import java.util.List;

public class MethodMatcherConfiguration {

    private HttpMethodMatcher get = new HttpMethodMatcher(HttpMethod.GET);
    private HttpMethodMatcher head = new HttpMethodMatcher(HttpMethod.HEAD);
    private HttpMethodMatcher post = new HttpMethodMatcher(HttpMethod.POST);
    private HttpMethodMatcher put = new HttpMethodMatcher(HttpMethod.PUT);
    private HttpMethodMatcher patch = new HttpMethodMatcher(HttpMethod.PATCH);
    private HttpMethodMatcher delete = new HttpMethodMatcher(HttpMethod.DELETE);
    private HttpMethodMatcher options = new HttpMethodMatcher(HttpMethod.OPTIONS);
    private HttpMethodMatcher trace = new HttpMethodMatcher(HttpMethod.TRACE);
    
    public HttpMethodMatcher getGet() {
        return get;
    }
    public void setGet(HttpMethodMatcher get) {
        this.get = get;
    }
    public HttpMethodMatcher getHead() {
        return head;
    }
    public void setHead(HttpMethodMatcher head) {
        this.head = head;
    }
    public HttpMethodMatcher getPost() {
        return post;
    }
    public void setPost(HttpMethodMatcher post) {
        this.post = post;
    }
    public HttpMethodMatcher getPut() {
        return put;
    }
    public void setPut(HttpMethodMatcher put) {
        this.put = put;
    }
    public HttpMethodMatcher getDelete() {
        return delete;
    }
    public void setDelete(HttpMethodMatcher delete) {
        this.delete = delete;
    }

    public HttpMethodMatcher getOptions() {
        return options;
    }
    public void setOptions(HttpMethodMatcher options) {
        this.options = options;
    }
    public HttpMethodMatcher getTrace() {
        return trace;
    }
    public void setTrace(HttpMethodMatcher trace) {
        this.trace = trace;
    }

    public HttpMethodMatcher getPatch() {
        return patch;
    }
    
    public void setPatch(HttpMethodMatcher patch) {
        this.patch = patch;
    }
    
    public boolean isActive() {
        return get.isActive() || head.isActive() || post.isActive() || put.isActive() || patch.isActive() || delete.isActive() || options.isActive() || trace.isActive();
    }
    
    public List<HttpMethodMatcher> getActiveMethods() {
        List<HttpMethodMatcher> list = new ArrayList<>();
        
        if (get.isActive()) {
            list.add(get);
        }
        if (head.isActive()) {
            list.add(head);
        }
        if (post.isActive()) {
            list.add(post);
        }
        if (put.isActive()) {
            list.add(put);
        }
        if (patch.isActive()) {
            list.add(patch);
        }
        if (delete.isActive()) {
            list.add(delete);
        }
        if (options.isActive()) {
            list.add(options);
        }
        if (trace.isActive()) {
            list.add(trace);
        }
        
        return list;
    }
}
