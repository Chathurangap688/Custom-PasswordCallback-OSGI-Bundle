package org.wso2.carbon.custom.user.passwordCallback.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.wso2.carbon.custom.user.passwordCallback.SecurityServiceHolder;
import org.wso2.carbon.user.core.service.RealmService;

@Component(name = "org.wso2.carbon.custom.user.passwordCallback.internal.PasswordCallbackServiceComponent",
        immediate = true)
public class PasswordCallbackServiceComponent {
    private static final Log log = LogFactory.getLog(PasswordCallbackServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {
        if (log.isDebugEnabled()) {
            log.debug("Custom component is activated.");
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext cxt) {

        if (log.isDebugEnabled()) {
            log.debug("Custom component is deactivated.");
        }
    }


    @Reference(name = "realm.service",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service");
        }
        SecurityServiceHolder.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Unset the Realm Service.");
        }
        SecurityServiceHolder.setRealmService(null);
    }
}
