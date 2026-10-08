/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.certgen;

import com.mirth.connect.model.ExtensionPermission;
import com.mirth.connect.plugins.ServicePlugin;

import java.util.Map;
import java.util.Properties;

/**
 * Registers the certificate generator. It keeps no state of its own: the CA key
 * pairs and the certificates it saves live in TLS Manager.
 */
public class CertGenServicePlugin implements ServicePlugin {

    public static final String PLUGIN_POINT_NAME = "Certificate Generator";

    @Override
    public void init(Properties properties) {
    }

    @Override
    public void start() {
    }

    @Override
    public void stop() {
    }

    @Override
    public void update(Properties properties) {
    }

    @Override
    public Properties getDefaultProperties() {
        return new Properties();
    }

    @Override
    public ExtensionPermission[] getExtensionPermissions() {
        return new ExtensionPermission[] {
            new ExtensionPermission(PLUGIN_POINT_NAME, "Generate certificates",
                "Allows issuing certificates signed by TLS Manager's CA key pairs, which "
                + "hands out keys the engine's partners will trust, so grant it as narrowly "
                + "as the permission to manage TLS Manager.",
                new String[] {"certGenAuthorities", "certGenIssue"},
                new String[0]),
        };
    }

    @Override
    public String getPluginPointName() {
        return PLUGIN_POINT_NAME;
    }

    @Override
    public Map<String, Object> getObjectsForSwaggerExamples() {
        return Map.of();
    }
}
