package cn.isekai.keycloak.webhook;

import cn.isekai.keycloak.webhook.federation.WebhookFederationProvider;
import lombok.Getter;
import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.ArrayList;
import java.util.List;

@Getter
public class WebhookConfig {
    private static final Logger logger = Logger.getLogger(WebhookFederationProvider.class);
    protected MultivaluedHashMap<String, String> config;

    public List<String> webhookList = new ArrayList<>();

    public WebhookConfig(MultivaluedHashMap<String, String> config){
        this.config = config;
        this.initialize();
    }

    public static List<ProviderConfigProperty> getConfigProps() {
        return ProviderConfigurationBuilder.create()
                .property().name("webhook-list")
                .label("Webhook list")
                .defaultValue("")
                .type(ProviderConfigProperty.MULTIVALUED_STRING_TYPE)
                .add()
                .build();
    }

    protected MultivaluedHashMap<String, String> getConfig() {
        return config;
    }

    protected void initialize(){
        if (this.config == null) return;

        this.webhookList = this.config.getList("webhook-list");
    }
}
