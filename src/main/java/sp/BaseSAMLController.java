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

import jakarta.servlet.http.HttpServletRequest;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.security.IdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.security.impl.Type4UUIDIdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.xml.ParserPool;

import java.util.function.Supplier;

import org.apache.velocity.app.VelocityEngine;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.decoder.servlet.BaseHttpServletRequestXMLMessageDecoder;
import org.opensaml.saml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPSOAP11Decoder;
import org.opensaml.security.credential.Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;

public abstract class BaseSAMLController {

    private Logger log = LoggerFactory.getLogger(BaseSAMLController.class);

    @Autowired protected XMLObjectBuilderFactory builderFactory;

    @Autowired protected MarshallerFactory marshallerFactory;

    protected IdentifierGenerationStrategy idGenerator = new Type4UUIDIdentifierGenerationStrategy();

    @Autowired protected VelocityEngine velocityEngine;
    
    @Autowired protected SAMLArtifactMap artifactMap;

    @Autowired protected ParserPool parserPool;

    @Autowired @Qualifier("test.sp.Credential") protected Credential spCredential;
    
    @Autowired protected ApplicationContext applicationContext;

    private void setRequest(final BaseHttpServletRequestXMLMessageDecoder decoder, final HttpServletRequest servletRequest) {
        decoder.setHttpServletRequestSupplier(new Supplier() {
            public HttpServletRequest get() {
                return servletRequest;
            }
        });
    }
    
    protected MessageContext decodeInboundMessageContextPost(HttpServletRequest servletRequest)
            throws Exception {
        HTTPPostDecoder decoder = new HTTPPostDecoder();
        try {
            setRequest(decoder, servletRequest);
            decoder.setParserPool(parserPool);
            decoder.initialize();

            decoder.decode();

            return decoder.getMessageContext();
        } catch (ComponentInitializationException | MessageDecodingException e) {
            log.error("Error decoding inbound message context", e);
            throw e;
        } finally {
            decoder.destroy();
        }
    }

    protected MessageContext decodeInboundMessageContextSOAP(HttpServletRequest servletRequest)
            throws Exception {
        HTTPSOAP11Decoder decoder = new HTTPSOAP11Decoder();
        try {
            setRequest(decoder, servletRequest);
            decoder.setParserPool(parserPool);
            decoder.initialize();

            decoder.decode();

            return decoder.getMessageContext();
        } catch (ComponentInitializationException | MessageDecodingException e) {
            log.error("Error decoding inbound message context", e);
            throw e;
        } finally {
            decoder.destroy();
        }
    }
    
    protected MessageContext decodeInboundMessageContextRedirect(HttpServletRequest servletRequest)
            throws Exception {
        HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
        try {
            setRequest(decoder, servletRequest);
            decoder.setParserPool(parserPool);
            decoder.initialize();

            decoder.decode();

            return decoder.getMessageContext();
        } catch (ComponentInitializationException | MessageDecodingException e) {
            log.error("Error decoding inbound message context", e);
            throw e;
        } finally {
            decoder.destroy();
        }
    }

}