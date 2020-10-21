package org.wso2.carbon.custom.user.passwordCallback;

import org.wso2.carbon.user.core.service.RealmService;

public class SecurityServiceHolder {
    private static RealmService realmService;
    public static void setRealmService(RealmService realmService) {

        SecurityServiceHolder.realmService = realmService;
    }
    public static RealmService getRealmService() throws Exception {
        if (realmService == null) {
            throw new SecurityConfigException("The main user realm is null");
        }
        return realmService;
    }
}
