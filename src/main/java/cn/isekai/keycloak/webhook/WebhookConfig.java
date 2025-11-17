package cn.isekai.keycloak.webhook;

import cn.isekai.keycloak.webhook.eventlistener.WebhookEventListenerProvider;
import cn.isekai.keycloak.webhook.federation.WebhookFederationProvider;
import cn.isekai.keycloak.webhook.federation.WebhookFederationProviderFactory;
import lombok.Getter;
import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderModel;

import java.util.ArrayList;
import java.util.List;

@Getter
public class WebhookConfig {
    private static final Logger logger = Logger.getLogger(WebhookFederationProvider.class);

    protected MultivaluedHashMap<String, String> config;

    public List<String> webhookList = new ArrayList<>();
    public boolean enableSignature = false;
    public String signatureSecret = "";

    public WebhookConfig(MultivaluedHashMap<String, String> config) {
        this.config = config;
        this.initialize();
    }

    public WebhookConfig() {
    }

    public static WebhookConfig fromRealm(RealmModel realm) {
        UserStorageProviderModel userStorage = realm.getComponentsStream()
                .filter(component -> component.getProviderType().equals(UserStorageProvider.class.getName())
                        && component.getProviderId().equals(WebhookFederationProviderFactory.PROVIDER_NAME))
                .map(UserStorageProviderModel::new)
                .findFirst()
                .orElse(null);

        if (userStorage != null) {
            MultivaluedHashMap<String, String> configMap = userStorage.getConfig();
            logger.debugf("Loaded webhook config for realm %s: %s", realm.getName(), configMap);
            return new WebhookConfig(configMap);
        } else {
            logger.debugf("No webhook config found for realm %s, using default config.", realm.getName());
            return new WebhookConfig();
        }
    }

    public static List<ProviderConfigProperty> getConfigProps() {
        return ProviderConfigurationBuilder.create()
                .property().name("webhook-list")
                .label("Webhook endpoints")
                .defaultValue("")
                .type(ProviderConfigProperty.MULTIVALUED_STRING_TYPE)
                .add()
                .property().name("webhook-enable-signature")
                .label("Enable Signature Header")
                .helpText("Signature will be added to X-Signature header, algorithm: sha256(secret + sha256(payload))")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .add()
                .property().name("webhook-signature-secret")
                .label("Signature Secret")
                .type(ProviderConfigProperty.PASSWORD)
                .add()
                .build();
    }

    protected void initialize() {
        if (this.config == null) return;

        this.webhookList = this.config.getList("webhook-list");
        this.enableSignature = Boolean.parseBoolean(this.config.getFirst("webhook-enable-signature"));
        this.signatureSecret = this.config.getFirst("webhook-signature-secret");
    }
}
