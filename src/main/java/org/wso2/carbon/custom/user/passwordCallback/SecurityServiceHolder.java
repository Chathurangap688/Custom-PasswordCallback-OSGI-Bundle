package org.wso2.carbon.custom.user.passwordCallback;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.user.core.service.RealmService;

public class SecurityServiceHolder {
    private static RealmService realmService;
    private static final Log log = LogFactory.getLog(SecurityServiceHolder.class);

    public static void setRealmService(RealmService realmService) {

        SecurityServiceHolder.realmService = realmService;
    }
    public static RealmService getRealmService() throws Exception {
        if (realmService == null) {
            log.error("realmService: null");
            throw new Exception("The main user realm is null");
        }
        return realmService;
    }
}
