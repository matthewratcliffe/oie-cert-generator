/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.certgen;

import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.core.Operation;
import com.mirth.connect.client.core.api.BaseServletInterface;
import com.mirth.connect.client.core.api.MirthOperation;
import com.mirth.connect.client.core.api.Param;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.Map;

/**
 * The certificate generator's API, under /api/certgen.
 *
 * <p>Maps in and out, XStream-shaped like the engine's own: the web console sends a
 * {@code <map>} body and reads the JSON form of the answer.
 */
@Path("/certgen")
@Consumes({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
@Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
public interface CertGenServletInterface extends BaseServletInterface {

    @GET
    @Path("/authorities")
    @io.swagger.v3.oas.annotations.Operation(summary =
        "TLS Manager's key pairs that can sign, and which one to offer first.")
    @MirthOperation(name = "certGenAuthorities", display = "List certificate authorities",
        auditable = false)
    Map<String, Object> getAuthorities() throws ClientException;

    @POST
    @Path("/issue")
    @io.swagger.v3.oas.annotations.Operation(summary =
        "Generate a key pair and a certificate for it signed by a CA key pair, save it in "
        + "TLS Manager and return it as PKCS#12 and PEM.")
    @MirthOperation(name = "certGenIssue", display = "Generate a certificate",
        type = Operation.ExecuteType.SYNC)
    Map<String, Object> issue(
        // The body carries the PKCS#12 password when one is given.
        @Param(value = "request", excludeFromAudit = true)
        @io.swagger.v3.oas.annotations.Parameter(description = "caAlias, subject, alias, "
            + "subjectAltNames, keyType, validityDays, pkcs12Password, save.")
        Map<String, String> request) throws ClientException;

    @POST
    @Path("/import")
    @io.swagger.v3.oas.annotations.Operation(summary =
        "Save a key pair given as PEM in TLS Manager, with its whole certificate chain, "
        + "so TLS connectors can present it.")
    @MirthOperation(name = "certGenImport", display = "Import a key pair",
        type = Operation.ExecuteType.SYNC)
    Map<String, Object> importKeyPair(
        // The body carries the private key.
        @Param(value = "request", excludeFromAudit = true)
        @io.swagger.v3.oas.annotations.Parameter(description = "alias, certificatePem, "
            + "privateKeyPem, replace.")
        Map<String, String> request) throws ClientException;
}
