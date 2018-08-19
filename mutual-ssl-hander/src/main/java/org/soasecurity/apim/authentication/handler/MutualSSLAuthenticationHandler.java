/*
 *  Copyright WSO2 Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.soasecurity.apim.authentication.handler;

import org.apache.axis2.Constants;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.synapse.*;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.wso2.carbon.apimgt.gateway.handlers.Utils;
import org.wso2.carbon.apimgt.gateway.handlers.security.APIAuthenticationHandler;


import java.util.HashMap;
import java.util.Map;


/**
 * Mutual SSL authentication handler for WSO2 APIM
 */
public class MutualSSLAuthenticationHandler extends APIAuthenticationHandler {

    private static final Log log = LogFactory.getLog(MutualSSLAuthenticationHandler.class);


    public void init(SynapseEnvironment synapseEnvironment) {

		if (log.isDebugEnabled()) {
			log.debug("Initializing API authentication handler instance");
		}
    }


    public boolean handleRequest(MessageContext messageContext) {


        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext).getAxis2MessageContext();

        // try to retrieve the certificate
        Object sslCertObject = axis2MessageContext.getProperty("ssl.client.auth.cert.X509");

        if(sslCertObject != null) {
            // if certificate is available in the MessageContext,  it means that mutual SSL validation has been done
            // and succeed in the transport level.
            // So, you can return tru here

            //return true;

            // Following are some additional steps

            // retrieve certificate
            javax.security.cert.X509Certificate[] certs = (javax.security.cert.X509Certificate[]) sslCertObject;
            javax.security.cert.X509Certificate x509Certificate = certs[0];

            // log the DN name of it
            String dn = x509Certificate.getSubjectDN().getName();
            log.info("Application is authenticate with certificate :  " + dn);

            // add certificate in to transport headers to send it to backend
            setCertificateAsHeader(axis2MessageContext, x509Certificate);

            return true;

        } else {
            // if certificate is not available in the MessageContext,  it means that mutual SSL validation has been failed
            // in the transport level.

            // send 401 to client
            handleAuthFailure(messageContext);

        }
        return false;
    }

    @Override
    public boolean handleResponse(MessageContext messageContext) {

        return true;
    }

    /**
     *
     * @param axis2MessageContext
     * @param x509Certificate
     */
    private void setCertificateAsHeader(org.apache.axis2.context.MessageContext axis2MessageContext,
                                        javax.security.cert.X509Certificate x509Certificate){

        try {
            byte[]  encodedData = x509Certificate.getEncoded();
            byte[] base64Encoded = Base64.encodeBase64(encodedData);

            Object headers = axis2MessageContext.getProperty(
                    org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

            if (headers != null && headers instanceof Map) {
                Map headersMap = (Map) headers;
                headersMap.put("SSL_CLIENT_CERT", new String(base64Encoded));
            }
            if (headers == null) {
                Map headersMap = new HashMap();
                headersMap.put("SSL_CLIENT_CERT", new String(base64Encoded));
                axis2MessageContext.setProperty(
                        org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS,
                        headersMap);
            }
        } catch (Exception e) {
            log.error("Error while adding client certificate to HTTP header",  e);
        }

    }

    private void handleAuthFailure(MessageContext messageContext) {


        org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) messageContext).
                getAxis2MessageContext();

        axis2MC.setProperty(Constants.Configuration.MESSAGE_TYPE, "application/soap+xml");
        int status = HttpStatus.SC_UNAUTHORIZED;
        Map<String, String> headers = new HashMap<String, String>();
        headers.put(HttpHeaders.WWW_AUTHENTICATE, "realm=\"WSO2 API Manager\"");
        axis2MC.setProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS, headers);

        Utils.sendFault(messageContext, status);
    }

}

