package io.alauda.oauth2.core;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;

import java.util.LinkedHashMap;
import java.util.Map;

public class UserInfoAuthenticationConverter extends DefaultUserAuthenticationConverter {

    @Override
    public Map<String,?> convertUserAuthentication(Authentication authentication) {
        LinkedHashMap response = new LinkedHashMap();
        UserInfo userInfo = (UserInfo) authentication.getPrincipal();
        response.put("user_id", userInfo.getId());
        response.put("user_name", authentication.getName());
        response.put("display_name", userInfo.getDisplayName());
        response.put("mail", userInfo.getMail());
        response.put("phone", userInfo.getPhone());
        response.put("avata", userInfo.getAvatar());

        if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
            response.put("authorities", AuthorityUtils.authorityListToSet(authentication.getAuthorities()));
        }

        return response;
    }
}
