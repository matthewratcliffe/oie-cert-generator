/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.certgen;

import com.mirth.connect.server.api.MirthServlet;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;
import java.util.Map;

public class CertGenServlet extends MirthServlet implements CertGenServletInterface {

    private static final CertGenService SERVICE = new CertGenService();

    public CertGenServlet(@Context HttpServletRequest request,
                          @Context SecurityContext securityContext) {
        super(request, securityContext, CertGenServicePlugin.PLUGIN_POINT_NAME);
    }

    @Override
    public Map<String, Object> getAuthorities() {
        return SERVICE.authorities();
    }

    @Override
    public Map<String, Object> issue(Map<String, String> request) {
        // Who asked, for the log line: the audit event records it by name.
        String user = context == null ? null : "user " + context.getUserId();
        return SERVICE.issue(request, user);
    }
}
