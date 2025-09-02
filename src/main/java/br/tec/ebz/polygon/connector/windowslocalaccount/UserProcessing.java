package br.tec.ebz.polygon.connector.windowslocalaccount;

import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.List;

public class UserProcessing extends ObjectProcessing {
    private static final Log LOG = Log.getLog(UserProcessing.class);

    private static final String NAME = "Name";
    private static final String SCHEMA_CLASS_NAME = "SchemaClassName";
    private static final String USER_FLAGS = "UserFlags";
    private static final String MAX_STORAGE = "MaxStorage";
    private static final String PASSWORD_AGE = "PasswordAge";
    private static final String PASSWORD_EXPIRED = "PasswordExpired";
    private static final String LOGIN_HOURS = "LoginHours";
    private static final String DESCRIPTION = "Description";
    private static final String FULL_NAME = "FullName";
    private static final String BAD_PASSWORD_ATTEMPTS = "BadPasswordAttempts";
    private static final String LAST_LOGIN = "LastLogin";
    private static final String HOME_DIRECTORY = "HomeDirectory";
    private static final String LOGIN_SCRIPT = "LoginScript";
    private static final String PROFILE = "Profile";
    private static final String HOME_DIR_DRIVE = "HomeDirDrive";
    private static final String PARAMETERS = "Parameters";
    private static final String PRIMARY_GROUP_ID = "PrimaryGroupId";
    private static final String MIN_PASSWORD_LENGTH = "MinPasswordLength";
    private static final String MAX_PASSWORD_AGE = "MaxPasswordAge";
    private static final String MIN_PASSWORD_AGE = "MinPasswordAge";
    private static final String PASSWORD_HISTORY_LENGTH = "PasswordHistoryLength";
    private static final String AUTO_UNLOCK_INTERVAL = "AutoUnlockInterval";
    private static final String LOCKOUT_OBSERVATION_INTERVAL = "LockoutObservationInterval";
    private static final String MAX_BAD_PASSWORDS_ALLOWED = "MaxBadPasswordsAllowed";
    private static final String OBJECT_SID = "objectSid";
    private static final String GROUPS = "groups";

    private final ZeroMQServerConnection connection;

    public UserProcessing(WindowsLocalAccountConfiguration configuration) throws CertificateException, IOException {
        connection = new ZeroMQServerConnection(configuration);
    }

    public void search(String query, ResultsHandler resultsHandler) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        if (query != null) {
            searchByQuery(query, resultsHandler);
        } else {
            searchAll(resultsHandler);
        }
    }


    private JSONArray searchUserGroups(JSONObject account) {
        JSONArray userGroups = new JSONArray();

        String accountName = getJsonAttributeValue(account, String.class, "Name");
        String request = "{\"requestType\": \"groupsFromAccount\", \"filter\": \"" + accountName + "\"}";

        JSONObject response = connection.send(request);
        LOG.ok("Response from server: {0}", response.toString());

        if (response.has("results")) {
            JSONArray groups = response.getJSONArray("results");

            for (Object object : groups) {
                String login = getJsonAttributeValue((JSONObject) object, String.class, NAME);
                userGroups.put(login);
            }
        }
        return userGroups;
    }


    private void searchByQuery(String query, ResultsHandler resultsHandler) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        LOG.info("Starting process to search windows account by query {0}", query);

        JSONObject response = connection.send(query);
        LOG.ok("Response from server: {0}", response.toString());

        try {
            JSONArray userGroups = searchUserGroups(response);
            response.put(GROUPS, userGroups);

            ConnectorObject connectorObject = translate(response);

            boolean result = resultsHandler.handle(connectorObject);
            LOG.info("Results handler result: {0}", result);
        } catch (Exception e) {
            LOG.warn("Could not process query {0}, reason: {1}", query, e.getMessage());
        }
    }

    private void searchAll(ResultsHandler resultsHandler) {
        String request = "{\"requestType\": \"allAccounts\"}";

        JSONObject response = connection.send(request);

        JSONArray accounts = response.getJSONArray("results");

        for (int i = 0; i < accounts.length() ; i++) {
            JSONObject account = accounts.getJSONObject(i);
            LOG.info("Processing account {0}", account.toString());

            JSONArray userGroups = searchUserGroups(account);
            account.put(GROUPS, userGroups);

            ConnectorObject connectorObject = translate(account);

            boolean result = resultsHandler.handle(connectorObject);

            LOG.info("Results handler result: {0}", result);
        }
    }


    private ConnectorObject translate(JSONObject account) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(ObjectClass.ACCOUNT);

        String name = getJsonAttributeValue(account, String.class, NAME);

        addAttribute(builder, Name.NAME, name);
        addAttribute(builder, Uid.NAME, name);
        addAttribute(builder, SCHEMA_CLASS_NAME, getJsonAttributeValue(account, String.class, SCHEMA_CLASS_NAME));
        addAttribute(builder, USER_FLAGS, getJsonAttributeValue(account, Integer.class, USER_FLAGS));
        addAttribute(builder, MAX_STORAGE, getJsonAttributeValue(account, Integer.class, MAX_STORAGE));
        addAttribute(builder, PASSWORD_AGE, getJsonAttributeValue(account, Integer.class, PASSWORD_AGE));
        addAttribute(builder, PASSWORD_EXPIRED, getJsonAttributeValue(account, Integer.class, PASSWORD_EXPIRED));
        addAttribute(builder, LOGIN_HOURS, getJsonAttributeValue(account, String.class, LOGIN_HOURS));
        addAttribute(builder, FULL_NAME, getJsonAttributeValue(account, String.class, FULL_NAME));
        addAttribute(builder, DESCRIPTION, getJsonAttributeValue(account, String.class, DESCRIPTION));
        addAttribute(builder, BAD_PASSWORD_ATTEMPTS, getJsonAttributeValue(account, Integer.class, BAD_PASSWORD_ATTEMPTS));
        addAttribute(builder, LAST_LOGIN, getJsonAttributeValue(account, String.class, LAST_LOGIN));
        addAttribute(builder, HOME_DIRECTORY, getJsonAttributeValue(account, String.class, HOME_DIRECTORY));
        addAttribute(builder, LOGIN_SCRIPT, getJsonAttributeValue(account, String.class, LOGIN_SCRIPT));
        addAttribute(builder, PROFILE, getJsonAttributeValue(account, String.class, PROFILE));
        addAttribute(builder, HOME_DIR_DRIVE, getJsonAttributeValue(account, String.class, HOME_DIR_DRIVE));
        addAttribute(builder, PARAMETERS, getJsonAttributeValue(account, String.class, PARAMETERS));
        addAttribute(builder, PRIMARY_GROUP_ID, getJsonAttributeValue(account, Integer.class, PRIMARY_GROUP_ID));
        addAttribute(builder, MIN_PASSWORD_LENGTH, getJsonAttributeValue(account, Integer.class, MIN_PASSWORD_LENGTH));
        addAttribute(builder, MAX_PASSWORD_AGE, getJsonAttributeValue(account, Integer.class, MAX_PASSWORD_AGE));
        addAttribute(builder, MIN_PASSWORD_AGE, getJsonAttributeValue(account, Integer.class, MIN_PASSWORD_AGE));
        addAttribute(builder, PASSWORD_HISTORY_LENGTH, getJsonAttributeValue(account, Integer.class, PASSWORD_HISTORY_LENGTH));
        addAttribute(builder, AUTO_UNLOCK_INTERVAL, getJsonAttributeValue(account, Integer.class, AUTO_UNLOCK_INTERVAL));
        addAttribute(builder, LOCKOUT_OBSERVATION_INTERVAL, getJsonAttributeValue(account, Integer.class, LOCKOUT_OBSERVATION_INTERVAL));
        addAttribute(builder, MAX_BAD_PASSWORDS_ALLOWED, getJsonAttributeValue(account, Integer.class, MAX_BAD_PASSWORDS_ALLOWED));
        addAttribute(builder, OBJECT_SID, getJsonAttributeValue(account, String.class, OBJECT_SID));

        addAttribute(builder, GROUPS, convertJSONArrayToList(account.getJSONArray(GROUPS)));

        return builder.build();
    }

    public ObjectClassInfo userSchemaBuilder() {
        ObjectClassInfoBuilder objectClassInfoBuilder = new ObjectClassInfoBuilder();
        objectClassInfoBuilder.setType(ObjectClass.ACCOUNT_NAME);

        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        Uid.NAME,
                        String.class,
                        Uid.NAME,
                        AttributeInfo.Flags.REQUIRED
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        Name.NAME,
                        String.class,
                        Name.NAME,
                        AttributeInfo.Flags.REQUIRED
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        SCHEMA_CLASS_NAME,
                        String.class,
                        SCHEMA_CLASS_NAME
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        USER_FLAGS,
                        Integer.class,
                        USER_FLAGS
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        MAX_STORAGE,
                        Integer.class,
                        MAX_STORAGE
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        PASSWORD_AGE,
                        Integer.class,
                        PASSWORD_AGE
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        PASSWORD_EXPIRED,
                        Integer.class,
                        PASSWORD_EXPIRED
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        LOGIN_HOURS,
                        String.class,
                        LOGIN_HOURS
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        FULL_NAME,
                        String.class,
                        FULL_NAME
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        DESCRIPTION,
                        String.class,
                        DESCRIPTION
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        BAD_PASSWORD_ATTEMPTS,
                        Integer.class,
                        BAD_PASSWORD_ATTEMPTS
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        LAST_LOGIN,
                        String.class,
                        LAST_LOGIN
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        HOME_DIRECTORY,
                        String.class,
                        HOME_DIRECTORY
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        LOGIN_SCRIPT,
                        String.class,
                        LOGIN_SCRIPT
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        PROFILE,
                        String.class,
                        PROFILE
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        HOME_DIR_DRIVE,
                        String.class,
                        HOME_DIR_DRIVE
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        PARAMETERS,
                        String.class,
                        PARAMETERS
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        PRIMARY_GROUP_ID,
                        Integer.class,
                        PRIMARY_GROUP_ID
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        MIN_PASSWORD_LENGTH,
                        Integer.class,
                        MIN_PASSWORD_LENGTH
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        MIN_PASSWORD_AGE,
                        Integer.class,
                        MIN_PASSWORD_AGE
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        PASSWORD_HISTORY_LENGTH,
                        Integer.class,
                        PASSWORD_HISTORY_LENGTH
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        AUTO_UNLOCK_INTERVAL,
                        Integer.class,
                        AUTO_UNLOCK_INTERVAL
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        LOCKOUT_OBSERVATION_INTERVAL,
                        Integer.class,
                        LOCKOUT_OBSERVATION_INTERVAL
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        MAX_BAD_PASSWORDS_ALLOWED,
                        Integer.class,
                        MAX_BAD_PASSWORDS_ALLOWED
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        MAX_PASSWORD_AGE,
                        Integer.class,
                        MAX_PASSWORD_AGE
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        OBJECT_SID,
                        String.class,
                        OBJECT_SID
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        GROUPS,
                        String.class,
                        GROUPS,
                        AttributeInfo.Flags.MULTIVALUED
                )
        );

        return objectClassInfoBuilder.build();
    }
}