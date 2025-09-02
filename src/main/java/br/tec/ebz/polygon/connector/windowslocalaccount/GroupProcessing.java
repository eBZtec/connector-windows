package br.tec.ebz.polygon.connector.windowslocalaccount;

import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.*;

public class GroupProcessing extends ObjectProcessing {
    private static final Log LOG = Log.getLog(GroupProcessing.class);

    private static final String NAME = "Name";
    private static final String DESCRIPTION = "Description";
    private static final String SCHEMA_CLASS_NAME= "SchemaClassName";
    private static final String GROUP_TYPE = "GroupType";
    private static final String OBJECT_SID = "ObjectSid";

    private final ZeroMQServerConnection connection;

    public GroupProcessing(WindowsLocalAccountConfiguration configuration){
        this.connection = new ZeroMQServerConnection(configuration);
    }

    public void search(String query, ResultsHandler resultsHandler) {
        if (query != null) {
            searchByQuery(query, resultsHandler);
        } else {
            searchAll(resultsHandler);
        }
    }

    private void searchByQuery(String query, ResultsHandler resultsHandler) {
        LOG.info("Starting process to search windows group by query {0}", query);

        JSONObject response = connection.send(query);
        LOG.ok("Response from server: {0}", response.toString());

        if (response.has("results")) {
            JSONArray groups = response.getJSONArray("results");
            processResults(groups, resultsHandler);

        } else {
            try {
                ConnectorObject connectorObject = translate(response);

                boolean result = resultsHandler.handle(connectorObject);
                LOG.info("Results handler result: {0}", result);
            } catch (Exception e) {
                LOG.warn("Could not process query {0}, reason: {1}", query, e.getMessage());
            }
        }
    }

    private void processResults(JSONArray results, ResultsHandler resultsHandler) {
        for (int i = 0; i < results.length() ; i++) {
            JSONObject object = results.getJSONObject(i);
            LOG.info("Processing group {0}", object.toString());

            ConnectorObject connectorObject = translate(object);

            boolean result = resultsHandler.handle(connectorObject);

            LOG.info("Results handler result: {0}", result);
        }
    }

    private void searchAll(ResultsHandler resultsHandler) {
        String request = "{\"requestType\": \"allGroups\"}";

        JSONObject response = connection.send(request);

        JSONArray accounts = response.getJSONArray("results");

        processResults(accounts, resultsHandler);
    }

    private ConnectorObject translate(JSONObject group)  {
        ConnectorObjectBuilder connectorObjectBuilder = new ConnectorObjectBuilder();
        connectorObjectBuilder.setObjectClass(ObjectClass.GROUP);

        String login = getJsonAttributeValue(group, String.class, NAME);

        addAttribute(connectorObjectBuilder, Name.NAME, login);
        addAttribute(connectorObjectBuilder, Uid.NAME, login);
        addAttribute(connectorObjectBuilder, NAME, login);
        addAttribute(connectorObjectBuilder, DESCRIPTION, getJsonAttributeValue(group, String.class, DESCRIPTION));
        addAttribute(connectorObjectBuilder, SCHEMA_CLASS_NAME, getJsonAttributeValue(group, String.class,  SCHEMA_CLASS_NAME));
        addAttribute(connectorObjectBuilder, GROUP_TYPE,  getJsonAttributeValue(group, Integer.class, GROUP_TYPE));
        addAttribute(connectorObjectBuilder, OBJECT_SID, getJsonAttributeValue(group, String.class, OBJECT_SID));

        return connectorObjectBuilder.build();
    }

    public ObjectClassInfo groupSchemaBuilder() {
        ObjectClassInfoBuilder objectClassInfoBuilder = new ObjectClassInfoBuilder();
        objectClassInfoBuilder.setType(ObjectClass.GROUP_NAME);

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
                        NAME,
                        String.class,
                        NAME,
                        AttributeInfo.Flags.REQUIRED
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
                        SCHEMA_CLASS_NAME,
                        String.class,
                        SCHEMA_CLASS_NAME
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        GROUP_TYPE,
                        Integer.class,
                        GROUP_TYPE
                )
        );
        objectClassInfoBuilder.addAttributeInfo(
                buildAttributeInfo(
                        OBJECT_SID,
                        String.class,
                        OBJECT_SID
                )
        );

        return objectClassInfoBuilder.build();
    }
}
