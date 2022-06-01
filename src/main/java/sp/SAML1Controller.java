/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sp;

import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.net.ssl.SSLContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.security.impl.SecureRandomIdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.cryptacular.util.CertUtil;
import org.cryptacular.util.KeyPairUtil;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.messaging.context.InOutOperationContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml1.core.AttributeQuery;
import org.opensaml.saml.saml1.core.NameIdentifier;
import org.opensaml.saml.saml1.core.Request;
import org.opensaml.saml.saml1.core.Response;
import org.opensaml.saml.saml1.core.Subject;
import org.opensaml.security.SecurityException;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.soap.client.http.HttpSOAPClient;
import org.opensaml.soap.messaging.context.SOAP11Context;
import org.opensaml.soap.soap11.Body;
import org.opensaml.soap.soap11.Envelope;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.HandlerMapping;
import org.w3c.dom.Element;

@Controller
@RequestMapping({"/SAML1", "/{spId}/SAML1"})
public class SAML1Controller extends BaseSAMLController {

    private final Logger log = LoggerFactory.getLogger(SAML1Controller.class);

    @RequestMapping(value = "/POST/ACS", method = RequestMethod.POST) public ResponseEntity<String>
            handleSSOResponsePOST(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
                    throws Exception {

        MessageContext messageContext = decodeInboundMessageContextPost(servletRequest);

        if (!(messageContext.getMessage() instanceof Response)) {
            log.error("Inbound message was not a SAML 1 Response");
            return new ResponseEntity<>("Inbound message was not a SAML 1 Response", HttpStatus.BAD_REQUEST);
        }

        Response response = (Response) messageContext.getMessage();
        Element responseElement = response.getDOM();
        String formattedMessage = SerializeSupport.prettyPrintXML(responseElement);
        log.trace("Returning response" + System.lineSeparator() + "{}", formattedMessage);

        // TODO instead of returning plain text via a ResponseEntity, add a JSP view that looks good

        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "text/plain");

        return new ResponseEntity<>(formattedMessage, headers, HttpStatus.OK);
    }

    private String getSpEntityId(HttpServletRequest servletRequest) {
        // TODO get from config somewhere
        final String spId = getSpId(servletRequest);
        return (spId == null) ? "https://sp.example.org" : "https://" + spId + ".example.org";
    }

    /**
     * Get the SP id as a path variable, or <code>null</code> if not present.
     * 
     * @param servletRequest the servlet request
     * @return the SP id or <code>null</code>
     */
    @Nullable private String getSpId(HttpServletRequest servletRequest) {
        final Object attr = servletRequest.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
        if (attr != null && attr instanceof Map) {
            final Map pathVariables = (Map) attr;
            final Object spId = pathVariables.get("spId");
            log.trace("Found spID '{}'", spId);
            if (spId != null) {
                return spId.toString();
            }
        }
        return null;
    }

    /**
     * Send a SAML 1 attribute query.
     * 
     * @param servletRequest the servlet request
     * @param servletResponse the servlet response
     * @param endpoint the endpoint to send the attribute query to
     * @param principalName the name of the principal to query for
     * @param trustedTLSCertificate the trusted IdP public certificate
     * @param trustedTLSCertificatePassword the IdP certificate password
     * @param clientTLSCertificate the SP public certificate
     * @param clientTLSPrivateKey the SP private key
     * @param clientTLSPassword the SP password
     * @param clientSigningCertificate ...
     * @param clientSigningPrivateKey ...
     * 
     * @return the SAML attribute query response is displayed
     * 
     * @throws Exception if an error occurs
     */
    @RequestMapping(value = "/AttributeQuery", method = RequestMethod.POST) public ResponseEntity<String>
            initSAML1AttributeQuery(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
                    @RequestParam(value = "endpoint", required = true) String endpoint,
                    @RequestParam(value = "principalName", required = true) String principalName,
                    @RequestParam(value = "trustedTLSCertificate", required = true) String trustedTLSCertificate,
                    @RequestParam(value = "trustedTLSCertificatePassword", required = true) String trustedTLSCertificatePassword,
                    @RequestParam(value = "clientTLSCertificate", required = false) String clientTLSCertificate,
                    @RequestParam(value = "clientTLSPrivateKey", required = true) String clientTLSPrivateKey,
                    @RequestParam(value = "clientTLSPassword", required = true) String clientTLSPassword,
                    @RequestParam(value = "clientSigningCertificate", required = false) String clientSigningCertificate,
                    @RequestParam(value = "clientSigningPrivateKey", required = false) String clientSigningPrivateKey)
                    throws Exception {

        final Resource trustedTLSCertificateResource = applicationContext.getResource(trustedTLSCertificate);
        log.debug("Trusted TLS certificate resource '{}'", trustedTLSCertificateResource);

        Resource clientTLSCertificateResource = null;
        if (StringSupport.trimOrNull(clientTLSCertificate) != null) {
            clientTLSCertificateResource = applicationContext.getResource(clientTLSCertificate);
        }
        log.debug("Client TLS certificate resource '{}'", clientTLSCertificateResource);

        final Resource clientTLSPrivateKeyResource = applicationContext.getResource(clientTLSPrivateKey);
        log.debug("Client TLS private key resource '{}'", clientTLSPrivateKeyResource);

        final HttpClient httpClient = buildHttpClient(trustedTLSCertificateResource, trustedTLSCertificatePassword,
                clientTLSCertificateResource, clientTLSPrivateKeyResource, clientTLSPassword);

        final HttpSOAPClient httpSoapClient = new HttpSOAPClient();
        httpSoapClient.setParserPool(parserPool);
        httpSoapClient.setHttpClient(httpClient);

        final Request attributeQuery = buildSAML1AttributeQueryRequest(servletRequest, principalName);

        // Sign if client signing certificate is present
        if (StringSupport.trimOrNull(clientSigningCertificate) != null) {
            sign(attributeQuery, clientSigningCertificate, clientSigningPrivateKey);
        }

        final Envelope envelope = buildSOAP11Envelope(attributeQuery);

        if (log.isDebugEnabled()) {
            log.debug("Sending AttributeQuery to endpoint '{}':\n", endpoint, SerializeSupport.prettyPrintXML(
                    marshallerFactory.getMarshaller(envelope).marshall(envelope, parserPool.newDocument())));
        }

        final InOutOperationContext context = SAML2Controller.buildInOutOperationContext(envelope);

        httpSoapClient.send(endpoint, context);

        final Envelope soapResponse =
                context.getInboundMessageContext().getSubcontext(SOAP11Context.class).getEnvelope();

        final String formattedMessage = SerializeSupport.prettyPrintXML(soapResponse.getDOM());

        final HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "text/plain");

        return new ResponseEntity<>(formattedMessage, headers, HttpStatus.OK);
    }

    /**
     * Builds a basic SAML 1 attribute query.
     * 
     * @param servletRequest ...
     * @param principalName the principal name
     * 
     * @return the attribute query
     */
    @Nonnull public Request buildSAML1AttributeQueryRequest(@Nonnull final HttpServletRequest servletRequest,
            @Nonnull final String principalName) {

        final Subject subject = buildSubject(principalName);

        final Request attributeQuery = buildAttributeQueryRequest(subject);
        attributeQuery.setIssueInstant(Instant.now());
        attributeQuery.setID(new SecureRandomIdentifierGenerationStrategy().generateIdentifier());
        attributeQuery.getAttributeQuery().setResource(getSpEntityId(servletRequest));

        // TODO AttributeDesignator

        return attributeQuery;
    }

    /**
     * Builds a {@link Subject}. If a principal name is given a {@link NameIdentifier}, whose value is the given
     * principal name, will be created and added to the {@link Subject}.
     * 
     * @param principalName the principal name to add to the subject
     * 
     * @return the built subject
     */
    @Nonnull public static Subject buildSubject(final @Nullable String principalName) {
        final SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().<Subject>getBuilderOrThrow(
                        Subject.DEFAULT_ELEMENT_NAME);
        final Subject subject = subjectBuilder.buildObject();

        if (principalName != null) {
            final SAMLObjectBuilder<NameIdentifier> nameIdBuilder = (SAMLObjectBuilder<NameIdentifier>)
                    XMLObjectProviderRegistrySupport.getBuilderFactory().<NameIdentifier>getBuilderOrThrow(
                            NameIdentifier.DEFAULT_ELEMENT_NAME);
            final NameIdentifier nameId = nameIdBuilder.buildObject();
            nameId.setValue(principalName);
            subject.setNameIdentifier(nameId);
        }

        return subject;
    }

    /**
     * Builds a {@link Request} containing an {@link AttributeQuery}. If a {@link Subject} is given, it will be added to
     * the constructed {@link AttributeQuery}.
     * 
     * @param subject the subject to add to the query
     * 
     * @return the built query
     */
    @Nonnull public static Request buildAttributeQueryRequest(final @Nullable Subject subject) {
        final SAMLObjectBuilder<AttributeQuery> queryBuilder = (SAMLObjectBuilder<AttributeQuery>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().<AttributeQuery>getBuilderOrThrow(
                        AttributeQuery.DEFAULT_ELEMENT_NAME);
        final AttributeQuery query = queryBuilder.buildObject();

        if (subject != null) {
            query.setSubject(subject);
        }

        final SAMLObjectBuilder<Request> requestBuilder = (SAMLObjectBuilder<Request>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().<Request>getBuilderOrThrow(
                        Request.DEFAULT_ELEMENT_NAME);
        final Request request = requestBuilder.buildObject();
        request.setID(new SecureRandomIdentifierGenerationStrategy().generateIdentifier());
        request.setIssueInstant(Instant.now());
        request.setQuery(query);
        request.setVersion(SAMLVersion.VERSION_11);

        return request;
    }
    
    /**
     * Build a SOAP11 {@link Envelope} with the given payload.
     * 
     * @param payload the payload
     * @return the SOAP11 envelop
     */
    @Nonnull public Envelope buildSOAP11Envelope(@Nonnull final XMLObject payload) {
        final Envelope envelope = XMLObjectProviderRegistrySupport.getBuilderFactory()
                .<Envelope> getBuilderOrThrow(Envelope.DEFAULT_ELEMENT_NAME).buildObject(Envelope.DEFAULT_ELEMENT_NAME);
        final Body body = XMLObjectProviderRegistrySupport.getBuilderFactory()
                .<Body> getBuilderOrThrow(Body.DEFAULT_ELEMENT_NAME).buildObject(Body.DEFAULT_ELEMENT_NAME);
        body.getUnknownXMLObjects().add(payload);
        envelope.setBody(body);
        return envelope;
    }

    @Nonnull public HttpClient buildHttpClient(@Nonnull final Resource trustedTLSCertificate,
            @Nonnull final String trustedTLSCertificatePassword, @Nullable final Resource clientTLSCertificate,
            @Nonnull final Resource clientTLSPrivateKey, @Nonnull final String clientTLSPassword) throws Exception {

        final KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(trustedTLSCertificate.getInputStream(), trustedTLSCertificatePassword.toCharArray());

        final PrivateKey clientPrivateKey = KeyPairUtil.readPrivateKey(clientTLSPrivateKey.getInputStream());

        X509Certificate clientCert = null;
        if (clientTLSCertificate != null) {
            clientCert = CertUtil.readCertificate(clientTLSCertificate.getInputStream());
        }

        final KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        keyStore.setKeyEntry("sp", clientPrivateKey, clientTLSPassword.toCharArray(), new Certificate[] {clientCert});

        final SSLContextBuilder sslContextBuilder = SSLContexts.custom();
        sslContextBuilder.loadTrustMaterial(trustStore);
        sslContextBuilder.loadKeyMaterial(keyStore, clientTLSPassword.toCharArray());

        final SSLContext sslcontext = sslContextBuilder.build();

        final CloseableHttpClient httpClient = HttpClients.custom().setSslcontext(sslcontext).build();

        return httpClient;
    }

    public void sign(@Nonnull final SignableXMLObject signable, @Nonnull final String certificate,
            @Nonnull final String privateKey)
            throws SecurityException, MarshallingException, SignatureException, XMLParserException, IOException {

        final Resource certificateResource = applicationContext.getResource(certificate);
        log.debug("Signing certificate resource '{}'", certificateResource);

        final Resource privateKeyResource = applicationContext.getResource(privateKey);
        log.debug("Signing private key resource '{}'", privateKeyResource);

        final X509Certificate cert = CertUtil.readCertificate(certificateResource.getInputStream());
        final PrivateKey key = KeyPairUtil.readPrivateKey(privateKeyResource.getInputStream());
        final BasicX509Credential cred = new BasicX509Credential(cert, key);

        final SignatureSigningParameters signingParameters = new SignatureSigningParameters();
        signingParameters.setSigningCredential(cred);
        signingParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signingParameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        SignatureSupport.signObject(signable, signingParameters);
    }

}
