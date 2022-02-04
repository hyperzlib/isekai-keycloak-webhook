package cn.isekai.keycloak.webhook.federation;

import cn.isekai.keycloak.webhook.WebhookConfig;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.storage.UserStorageProviderFactory;

import java.util.List;

public class WebhookFederationProviderFactory implements UserStorageProviderFactory<WebhookFederationProvider> {
    private static final Logger logger = Logger.getLogger(WebhookFederationProviderFactory.class);
    public static final String PROVIDER_NAME = "webhook";

    @Override
    public WebhookFederationProvider create(KeycloakSession session, ComponentModel model) {
        return new WebhookFederationProvider(session, model, this);
    }

    @Override
    public String getId() {
        return PROVIDER_NAME;
    }

    @Override
    public String getHelpText() {
        return "Call webhook when users change their data";
    }

    protected static final List<ProviderConfigProperty> configProperties;

    static {
        configProperties = WebhookConfig.getConfigProps();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }


    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }
}
