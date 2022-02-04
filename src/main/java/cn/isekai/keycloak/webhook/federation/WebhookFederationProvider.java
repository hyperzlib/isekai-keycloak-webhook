package cn.isekai.keycloak.webhook.federation;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.storage.UserStorageProvider;

public class WebhookFederationProvider implements UserStorageProvider {
    private static final Logger logger = Logger.getLogger(WebhookFederationProvider.class);

    public WebhookFederationProvider(KeycloakSession session, ComponentModel model,
                                     WebhookFederationProviderFactory factory) {

    }

    @Override
    public void preRemove(RealmModel realm) {

    }

    @Override
    public void preRemove(RealmModel realm, RoleModel role) {

    }

    @Override
    public void preRemove(RealmModel realm, GroupModel group) {

    }

    @Override
    public void close() {

    }
}