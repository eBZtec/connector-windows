/*
 * Copyright (c) 2010-2014 Evolveum
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package br.tec.ebz.polygon.connector.windowslocalaccount;

import kong.unirest.json.JSONObject;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.Connector;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.operations.SchemaOp;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.TestOp;

import java.util.List;

@ConnectorClass(displayNameKey = "windowslocalaccount.connector.display", configurationClass = WindowsLocalAccountConfiguration.class)
public class WindowsLocalAccountConnector implements Connector, TestOp, SearchOp<Filter>, SchemaOp {

    private static final Log LOG = Log.getLog(WindowsLocalAccountConnector.class);

    private WindowsLocalAccountConfiguration configuration;
    private WindowsLocalAccountConnection connection;
    private ZeroMQServerConnection zeroMQServerConnection;

    @Override
    public Configuration getConfiguration() {
        return configuration;
    }

    @Override
    public void init(Configuration configuration) {
        try {
            this.configuration = (WindowsLocalAccountConfiguration) configuration;
            this.zeroMQServerConnection = new ZeroMQServerConnection(this.configuration);
        } catch (ConfigurationException c) {
            throw new ConfigurationException(c.getMessage());
        } catch (Exception e) {
            throw new ConnectionFailedException("Could not connect to ZeroMQ server, reason: " + e.getMessage());
        }
    }

    @Override
    public void dispose() {
        configuration = null;
        if (connection != null) {
            connection.dispose();
            connection = null;
        }
    }

    @Override
    public void test() {
        try {
            JSONObject json = new JSONObject();
            json.put("requestType", "ping");
            JSONObject response = zeroMQServerConnection.send(json.toString());

            if (response.has("message")) {
                String message = response.getString("message");
                LOG.ok("Message \"{0}\" replied from server", message);
            } else {
                throw new ConnectionFailedException(response.getString("error"));
            }
            LOG.ok("Connected successfully to the server");

        } catch (Exception e) {
            LOG.error("Could not connect to ZeroMQ server: {0}", e.getMessage());
            throw new ConnectionFailedException("Could not connect to ZeroMQ server: " + e.getMessage());
        }
    }

    @Override
    public FilterTranslator<Filter> createFilterTranslator(ObjectClass objectClass, OperationOptions operationOptions) {
        return new FilterTranslator<Filter>() {
            @Override
            public List<Filter> translate(Filter filter) {
                return CollectionUtil.newList(filter);
            }
        };
    }

    @Override
    public void executeQuery(ObjectClass objectClass, Filter filter, ResultsHandler resultsHandler, OperationOptions operationOptions) {
        String query = null;

        if (filter != null) {
            query = filter.accept(new FilterHandler(objectClass), "");
            LOG.info("Query will be executed with the following filter: {0}", query);
            LOG.info("The object class from which the filter will be executed: {0}", objectClass.getDisplayNameKey());
        }

        try {

            if (ObjectClass.ACCOUNT.equals(objectClass)) {
                UserProcessing userProcessing = new UserProcessing(configuration);
                userProcessing.search(query, resultsHandler);
            } else if (ObjectClass.GROUP.equals(objectClass)) {
                GroupProcessing groupProcessing = new GroupProcessing(configuration);
                groupProcessing.search(query, resultsHandler);
            } else {
                throw new UnsupportedOperationException("Could not search object, type " + objectClass.getDisplayNameKey() + " does not exists");
            }

        } catch (Exception e) {
            LOG.error("Failed to process search operation, reason {0}", e);
            throw new ConnectorException("Failed to process search operation, reason " + e.getMessage());
        }
    }

    @Override
    public Schema schema() {
        SchemaBuilder schemaBuilder = new SchemaBuilder(WindowsLocalAccountConnector.class);

        GroupProcessing groupProcessing = new GroupProcessing(this.configuration);
        schemaBuilder.defineObjectClass(groupProcessing.groupSchemaBuilder());

        UserProcessing userProcessing = null;
        try {
            userProcessing = new UserProcessing(this.configuration);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        schemaBuilder.defineObjectClass(userProcessing.userSchemaBuilder());

        return schemaBuilder.build();
    }
}
