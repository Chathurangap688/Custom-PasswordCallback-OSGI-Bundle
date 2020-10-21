package org.wso2.carbon.custom.user.passwordCallback;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSPasswordCallback;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.registry.api.Registry;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.util.regex.Pattern;

public class PasswordCallbackHandler implements CallbackHandler {
    private static final Log log = LogFactory.getLog(PasswordCallbackHandler.class);
    private String serviceGroupId = null;
    private String serviceId = null;
    private Registry registry = null;
    private UserRealm realm = null;
    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        log.info("*****************************************************************************\n\n\n\n\n***********");
        for (int i = 0; i < callbacks.length; i++) {
            WSPasswordCallback passwordCallback = (WSPasswordCallback) callbacks[i];
            String username = passwordCallback.getIdentifer();
            String receivedPasswd = null;
            switch (passwordCallback.getUsage()) {
                case WSPasswordCallback.USERNAME_TOKEN_UNKNOWN:

                    receivedPasswd = passwordCallback.getPassword();
                    try {
                        if (receivedPasswd != null
                                && this.authenticateUser(username, receivedPasswd)) {

                            String domainName = UserCoreUtil.getDomainFromThreadLocal();
                            String usernameWithDomain = IdentityUtil.addDomainToName(username, domainName);
                            if (log.isDebugEnabled()) {
                                log.debug("Updating username with userstore domain. Updated username is :" +
                                        usernameWithDomain);
                            }
                            passwordCallback.setIdentifier(usernameWithDomain);
                        } else {
                            throw new UnsupportedCallbackException(callbacks[i], "check failed");
                        }
                    } catch (Exception e) {
                        if (log.isDebugEnabled()) {
                            log.debug("Error when authenticating user : " + username + ", password provided : "
                                    + StringUtils.isNotEmpty(receivedPasswd), e);
                        }
                        throw new UnsupportedCallbackException(callbacks[i],
                                "Check failed : System error");
                    }

                    break;

            }
        }
    }

    /**
     * this method can be use validate email format
     * @param email
     * @return true/false
     */
    public static boolean isValidEmail(String email)
    {
//        String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\."+
//                "[a-zA-Z0-9_+&*-]+)*@" +
//                "(?:[a-zA-Z0-9-]+\\.)+[a-z" +
//                "A-Z]{2,7}$";
        String emailRegex ="^[\\w-_\\.+]*[\\w-_\\.]\\@([\\w]+\\.)+[\\w]+[\\w]$";

        Pattern pat = Pattern.compile(emailRegex);
        if (email == null)
            return false;
        return pat.matcher(email).matches();
    }

    /**
     *
     * @param user
     * @param password
     * @return
     * @throws Exception
     */
    public boolean authenticateUser(String user, String password) throws Exception {
        boolean isAuthenticated = false;
        boolean isAuthorized = false;
        realm = (UserRealm) SecurityServiceHolder.getRealmService().getTenantUserRealm(-1234);
        if(isValidEmail(user)){
            log.info("Get username by email..");
            String[] userList = realm.getUserStoreManager().getUserList("http://wso2.org/claims/emailaddress",  user, null);
            if(userList.length == 1){
                user = userList[0];
            }else {
                log.error("Email is not available");
                return false;
            }
            user = userList[0];
        }
        try {
            // Verify whether user is in same tenant that service has been deployed.
            if (realm.getUserStoreManager().getTenantId() !=
                    SecurityServiceHolder.getRealmService().getTenantManager().getTenantId(MultitenantUtils.getTenantDomain(user))) {
                if (log.isDebugEnabled()) {
                    log.debug("User : " + user + " trying access service which is deployed in different tenant domain");
                }
                return false;
            }

            String tenantAwareUserName = MultitenantUtils.getTenantAwareUsername(user);

            isAuthenticated = realm.getUserStoreManager().authenticate(
                    tenantAwareUserName, password);

            if (isAuthenticated) {

                int index = tenantAwareUserName.indexOf("/");
                if (index < 0) {
                    String domain = UserCoreUtil.getDomainFromThreadLocal();
                    if (domain != null) {
                        tenantAwareUserName = domain + "/" + tenantAwareUserName;
                    }
                }

                isAuthorized = realm.getAuthorizationManager()
                        .isUserAuthorized(tenantAwareUserName,
                                "org.wso2.carbon.sts-5.5.1/wso2carbon-sts",
                                UserCoreConstants.INVOKE_SERVICE_PERMISSION);
                if (!isAuthorized) {
                    if (log.isDebugEnabled()) {
                        log.debug("Authorization failure for user : " + tenantAwareUserName);
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Authentication failure for user : " + tenantAwareUserName);
                }
            }

            return isAuthorized;
        } catch (Exception e) {
            log.error("Error in authenticating user.", e);
            throw e;
        }
    }
}
