package cn.isekai.keycloak.webhook.eventlistener;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpRequest;
import org.apache.http.NoHttpResponseException;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.EntityBuilder;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.jboss.logging.Logger;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerTransaction;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.storage.UserStorageProviderModel;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.reflect.Field;
import java.net.UnknownHostException;
import java.util.*;
import java.util.function.BiFunction;

public class WebhookEvenntListenerProvider implements EventListenerProvider {
    private static final Logger logger = Logger.getLogger(WebhookEvenntListenerProvider.class);
    // private final static Map<String, WebhookConfig> REALM_CONFIG = new HashMap<>();

    private final KeycloakSession session;
    private final RealmProvider model;
    private final Set<EventType> includedEvents;
    private final EventListenerTransaction tx = new EventListenerTransaction(null, this::sendWebhook);
    private final KeycloakUriInfo uriInfo;
    private final ClientConnection clientConnection;
    private static final int cacheExpires = 5000;

    private String[] cachedWebhookList = null;
    private long cachedWebhookListExpires = 0;

    private final static HttpRequestRetryHandler httpRequestRetryHandler = (exception, executionCount, context) -> {
        if (executionCount >= 5) {// 如果已经重试了5次，就放弃
            return false;
        }
        if (exception instanceof NoHttpResponseException) {// 如果服务器丢掉了连接，那么就重试
            return true;
        }
        if (exception instanceof SSLHandshakeException) {// 不要重试SSL握手异常
            return false;
        }
        if (exception instanceof InterruptedIOException) {// 超时
            return false;
        }
        if (exception instanceof UnknownHostException) {// 目标服务器不可达
            return false;
        }
        if (exception instanceof SSLException) {// SSL握手异常
            return false;
        }

        HttpClientContext clientContext = HttpClientContext
                .adapt(context);
        HttpRequest request = clientContext.getRequest();
        // 如果请求是幂等的，就再次尝试
        return !(request instanceof HttpEntityEnclosingRequest);
    };

    public WebhookEvenntListenerProvider(KeycloakSession session, Set<EventType> includedEvents) {
        this.session = session;
        this.model = session.realms();
        this.includedEvents = includedEvents;

        this.uriInfo = session.getContext().getUri();
        this.clientConnection = session.getContext().getConnection();

        this.session.getTransactionManager().enlistAfterCompletion(tx);
    }

    public String[] getWebhookList(RealmModel realm) {
        long currentTime = new Date().getTime();
        if (cachedWebhookList != null && currentTime < cachedWebhookListExpires) {
            return cachedWebhookList;
        }
        UserStorageProviderModel userStorage = realm.getUserStorageProvidersStream()
                .filter(model -> model.getProviderId().equals("webhook"))
                .findFirst().orElse(null);

        if (userStorage != null) {
            MultivaluedHashMap<String, String> configMap = userStorage.getConfig();
            List<String> webhookList = configMap.getList("webhook-list");
            if (webhookList != null) {
                cachedWebhookList = webhookList.toArray(new String[0]);
                cachedWebhookListExpires = currentTime + cacheExpires;
            }
        }
        return new String[0];
    }

    private static CloseableHttpClient getHttpClient() {
        RequestConfig requestConfig = RequestConfig.custom()
                .setSocketTimeout(2000)
                .setConnectTimeout(2000)
                .build();

        return HttpClientBuilder.create()
                .setDefaultRequestConfig(requestConfig)
                .setRetryHandler(httpRequestRetryHandler).build();
    }

    @Override
    public void onEvent(Event event) {
        if (includedEvents.contains(event.getType())) {
            if (event.getRealmId() != null && event.getUserId() != null) {
                ObjectMapper mapper = new ObjectMapper();

                if (event.getType() == EventType.UPDATE_PROFILE) {
                    // 增加用户信息
                    try {
                        Map<String, Object> userInfo = getUserInfo(event);
                        String userInfoJson = mapper.writeValueAsString(userInfo);
                        event.getDetails().put("user_info", userInfoJson);
                    } catch (Exception e) {
                        logger.error("Cannot get user info", e);
                    }
                }

                tx.addEvent(event);
            }
        }
    }

    private static Map<String, Object> objectToMap(Object obj) throws Exception {
        if (obj == null) {
            return null;
        }

        Map<String, Object> map = new HashMap<>();

        Field[] declaredFields = obj.getClass().getDeclaredFields();
        for (Field field : declaredFields) {
            field.setAccessible(true);
            map.put(field.getName(), field.get(obj));
        }

        return map;
    }

    private void sendWebhook(Event event) {
        RealmModel realm = model.getRealm(event.getRealmId());
        String[] webhookList = getWebhookList(realm);

        logger.info("Sending webhook: " + event.getType());
        if (webhookList.length > 0) {
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> eventContent = null;
            try {
                eventContent = objectToMap(event);
            } catch (Exception e) {
                logger.error("Cannot transform event to Map", e);
            }

            if (eventContent != null) {
                // decode user info
                try {
                    Map<String, String> eventDetail = event.getDetails();
                    if (eventDetail.containsKey("user_info")) {
                        String userInfoJson = eventDetail.get("user_info");
                        eventDetail.remove("user_info");
                        Map<String, Object> userInfo = mapper.readValue(userInfoJson, Map.class);
                        eventContent.put("userInfo", userInfo);
                    }
                } catch (Exception e) {
                    logger.error("Cannot transform event to Map", e);
                }
                doWebhookRequest(webhookList, eventContent);
            }
        }
    }

    private void doWebhookRequest(String[] webhookList, Map<String, Object> event) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            String eventJson = mapper.writeValueAsString(event);

            WebhookRequest request = new WebhookRequest(webhookList, eventJson);
            request.start();
        } catch (JsonProcessingException ex) {
            logger.error("Serialize event error", ex);
        }
    }

    private Map<String, Object> getUserInfo(Event event) {
        RealmModel realm = session.realms().getRealm(event.getRealmId());
        ClientModel client = realm.getMasterAdminClient();
        UserModel user = session.users().getUserById(realm, event.getUserId());
        return sessionAware(realm, client, user, (userSession, clientSessionCtx) -> {
            AccessToken userInfo = new AccessToken();
            TokenManager tokenManager = new TokenManager();

            tokenManager.transformUserInfoAccessToken(session, userInfo, userSession, clientSessionCtx);
            return tokenManager.generateUserInfoClaims(userInfo, user);
        });
    }

    private<R> R sessionAware(RealmModel realm, ClientModel client, UserModel user,
                              BiFunction<UserSessionModel, ClientSessionContext, R> function) {
        AuthenticationSessionModel authSession = null;
        AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);

        try {
            RootAuthenticationSessionModel rootAuthSession = authSessionManager.createAuthenticationSession(realm, false);

            authSession = rootAuthSession.createAuthenticationSession(client);

            authSession.setAuthenticatedUser(user);
            authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
            authSession.setClientNote(OIDCLoginProtocol.ISSUER, Urls.realmIssuer(uriInfo.getBaseUri(), realm.getName()));
            authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, null);

            session.getContext().getConnection().getRemoteAddr();

            UserSessionModel userSession = session.sessions().createUserSession(authSession.getParentSession().getId(), realm, user, user.getUsername(),
                    clientConnection.getRemoteAddr(), "example-auth", false, null, null, UserSessionModel.SessionPersistenceState.TRANSIENT);

            AuthenticationManager.setClientScopesInSession(authSession);
            ClientSessionContext clientSessionCtx = TokenManager.attachAuthenticationSession(session, userSession, authSession);

            return function.apply(userSession, clientSessionCtx);
        } finally {
            if (authSession != null) {
                authSessionManager.removeAuthenticationSession(realm, authSession, false);
            }
        }
    }

    static class WebhookRequest extends Thread {
        private final String[] webhookUrlList;
        private final String eventJson;

        public WebhookRequest(String[] webhookUrlList, String eventJson) {
            this.webhookUrlList = webhookUrlList;
            this.eventJson = eventJson;
        }

        @Override
        public void run() {
            for (String webhookUrl : webhookUrlList) {
                doSingleWebhookRequest(webhookUrl);
            }
        }

        private void doSingleWebhookRequest(String webhookUrl) {
            try (CloseableHttpClient client = getHttpClient()) {
                HttpPost post = new HttpPost(webhookUrl);

                // logger.info(eventJson);

                HttpEntity entity = EntityBuilder.create()
                        .setContentType(ContentType.APPLICATION_JSON).setText(eventJson).build();
                post.setEntity(entity);

                CloseableHttpResponse response = client.execute(post);

                //logger.info("Webhook sent to " + webhookUrl + ": " + response.getStatusLine().getStatusCode());

                response.close();
            } catch (IOException ex) {
                logger.error("Webhook send to " + webhookUrl + " error", ex);
            }
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean b) {

    }

    @Override
    public void close() {

    }
}
