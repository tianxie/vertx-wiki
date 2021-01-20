package com.zvos.iothub.user.security.jwt;

import com.google.gson.Gson;
import com.zvos.common.utils.StringUtil;
import com.zvos.common.utils.http.SessionModel;
import com.zvos.common.utils.token.AuthenticationTokenDTO;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Enumeration;

/**
 * Filters incoming requests and installs a Spring Security principal if a header corresponding to a valid user is
 * found.
 */
public class JWTFilter extends GenericFilterBean {
    //API网关计算的签名
    public static final String CA_PROXY_SIGN = "X-Ca-Proxy-Signature";
    //API网关用于计算签名的密钥Key
    public static final String CA_PROXY_SIGN_SECRET_KEY = "X-Ca-Proxy-Signature-Secret-Key";
    private static Gson gson = new Gson();

    static Logger LOG = LoggerFactory.getLogger(JWTFilter.class);
    private TokenProvider tokenProvider;
    private StringRedisTemplate stringRedisTemplate;
    public JWTFilter(TokenProvider tokenProvider,StringRedisTemplate stringRedisTemplate) {
        this.tokenProvider = tokenProvider;
        this.stringRedisTemplate = stringRedisTemplate;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        String jwt = resolveToken(httpServletRequest);
        LOG.debug( String.format("token is %s", jwt));
        LOG.debug( String.format("tokenProvider is %b", (null == tokenProvider) ));
        if (StringUtils.hasText(jwt)
                && this.tokenProvider.validateToken(jwt)
                && this.checkTokenValid(jwt)) {
            LOG.debug( String.format("token is valid, token=%s" , jwt ));
            Claims claims = this.tokenProvider.getAuthentication(jwt);
            SecurityContextHolder.getContext().setAuthentication(tokenProvider.getAuthenticationFromClaims(claims));
        }else if(isSignRequest(httpServletRequest)){
            String sessStr = httpServletRequest.getHeader("session");
            if(StringUtil.isNotBlank(sessStr)) {
                SessionModel session = gson.fromJson(sessStr, SessionModel.class);
                SecurityContextHolder.getContext().setAuthentication(getAuthenticationFromClaims(session));
            }
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    private boolean checkTokenValid(String jwt) {
        return stringRedisTemplate.hasKey(jwt);
    }

    public Authentication getAuthenticationFromClaims(SessionModel sessionModel) {
        String login = "" + sessionModel.getUserId();
        Long userId = sessionModel.getUserId();
        Long companyId = sessionModel.getCompanyId();
        Long deptId = sessionModel.getDeptId();
        AuthenticationTokenDTO token = new AuthenticationTokenDTO();
        token.setLogin(login);
        token.setUserId(userId);
        token.setCompanyId(companyId);
        token.setDeptId(deptId);
        return new UsernamePasswordAuthenticationToken(login, token);
    }

    public static boolean isSignRequest(HttpServletRequest request){
        Enumeration<String> names = request.getHeaderNames();
        boolean hasSign = false;
        boolean hasSignKey = false;
        while (names.hasMoreElements()){
            String name = names.nextElement();
            if( name.equalsIgnoreCase(CA_PROXY_SIGN) ){
                hasSign = true;
                if( hasSign && hasSignKey ){
                    return true;
                }
            }else if(name.equalsIgnoreCase(CA_PROXY_SIGN_SECRET_KEY)){
                hasSignKey = true;
                if( hasSign && hasSignKey ){
                    return true;
                }
            }
        }
        return false;
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(JWTConfigurer.AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }
}
