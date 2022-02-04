package cn.isekai.keycloak.webhook.eventlistener;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class WebhookEventListenerProviderFactory implements EventListenerProviderFactory {
    private static final Set<EventType> includedEvents = new HashSet<>();

    static {
        Collections.addAll(includedEvents, EventType.UPDATE_PASSWORD, EventType.UPDATE_EMAIL, EventType.UPDATE_PROFILE, EventType.LOGIN, EventType.LOGOUT);
    }

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new WebhookEvenntListenerProvider(session, includedEvents);
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

    @Override
    public String getId() {
        return "webhook-sender";
    }
}
