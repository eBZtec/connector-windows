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

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.spi.ConfigurationProperty;

import java.io.File;

public class WindowsLocalAccountConfiguration extends AbstractConfiguration {

    private static final Log LOG = Log.getLog(WindowsLocalAccountConfiguration.class);

    private String host;
    private String hostsCA;
    private String windowsHost;
    private String keystoreFile;
    private GuardedString getKeystorePassword;
    private String resourceID;
    private GuardedString resourceSecret;
    private int serverReceiveTimeout = 5000;

    @Override
    public void validate() {
        //todo implement
    }

    @ConfigurationProperty(
            displayMessageKey = "windowslocalaccount.config.host",
            helpMessageKey = "windowslocalaccount.config.host.help",
            order = 1,
            required = true
    )
    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    @ConfigurationProperty(
            displayMessageKey = "windowslocalaccount.config.hostCA",
            helpMessageKey = "windowslocalaccount.config.hostCA.help",
            order = 2,
            required = true

    )
    public String getHostsCA() {
        return hostsCA;
    }

    public void setHostsCA(String hostCA) {
        this.hostsCA = hostCA;
    }

    @ConfigurationProperty(
            displayMessageKey = "windowslocalaccount.config.windowsHost",
            helpMessageKey = "windowslocalaccount.config.windowsHost.help",
            order = 3,
            required = true
    )
    public String getWindowsHost() {
        return windowsHost;
    }

    public void setWindowsHost(String windowsHost) {
        this.windowsHost = windowsHost;
    }

    @ConfigurationProperty(
            displayMessageKey = "windowslocalaccount.config.keystoreFile",
            helpMessageKey = "windowslocalaccount.config.keystoreFile.help",
            order = 4,
            required = true

    )
    public String getKeystoreFile() { return keystoreFile; }

    public void setKeystoreFile(String keystorePath) {
        this.keystoreFile = new File(keystorePath).getAbsolutePath();
    }

    @ConfigurationProperty(
            displayMessageKey = "windowslocalaccount.config.keystorePassword",
            helpMessageKey = "windowslocalaccount.config.keystorePassword.help",
            order = 5,
            required = true,
            confidential = true

    )
    public GuardedString getKeystorePassword() { return getKeystorePassword; }

    public void setKeystorePassword(GuardedString password) { this.getKeystorePassword = password; }

    @ConfigurationProperty(
            displayMessageKey = "windowslocalaccount.config.resourceID",
            helpMessageKey = "windowslocalaccount.config.resourceID.help",
            order = 6,
            required = true

    )
    public String getResourceID() {
        return resourceID;
    }

    public void setResourceID(String resourceID) {
        this.resourceID = resourceID;
    }

    @ConfigurationProperty(
            displayMessageKey = "windowslocalaccount.config.resourceSecret",
            helpMessageKey = "windowslocalaccount.config.resourceSecret.help",
            order = 7,
            required = true

    )
    public GuardedString getResourceSecret() {
        return resourceSecret;
    }

    public void setResourceSecret(GuardedString resourceSecret) {
        this.resourceSecret = resourceSecret;
    }


    @ConfigurationProperty(
            displayMessageKey = "windowslocalaccount.config.serverReceiveTimeout",
            helpMessageKey = "windowslocalaccount.config.serverReceiveTimeout.help",
            order = 8,
            required = true

    )
    public int getServerReceiveTimeout() {
        return serverReceiveTimeout;
    }

    public void setServerReceiveTimeout(int serverReceiveTimeout) {
        this.serverReceiveTimeout = serverReceiveTimeout;
    }
}