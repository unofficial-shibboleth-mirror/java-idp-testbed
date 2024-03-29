package sp;

import java.io.IOException;
import java.net.MalformedURLException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Map;
import java.util.function.Supplier;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.net.ssl.SSLContext;

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
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.messaging.encoder.servlet.AbstractHttpServletResponseMessageEncoder;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.messaging.SAMLMessageSecuritySupport;
import org.opensaml.saml.common.messaging.context.SAMLArtifactContext;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.messaging.context.SAMLSelfEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.reqattr.RequestedAttributes;
import org.opensaml.saml.ext.saml2aslo.Asynchronous;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPArtifactEncoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPSOAP11Encoder;
import org.opensaml.saml.saml2.core.AttributeQuery;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.IDPEntry;
import org.opensaml.saml.saml2.core.IDPList;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.RequesterID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Scoping;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.RequestedAttribute;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.SecurityException;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.soap.client.http.HttpSOAPClient;
import org.opensaml.soap.messaging.context.SOAP11Context;
import org.opensaml.soap.soap11.Body;
import org.opensaml.soap.soap11.Envelope;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.net.URLBuilder;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.security.impl.SecureRandomIdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;

@Controller
@RequestMapping({"/SAML2", "/{spId}/SAML2"})
public class SAML2Controller extends BaseSAMLController {
	
	private final Logger log = LoggerFactory.getLogger(SAML2Controller.class);

	@RequestMapping(value="/InitSSO/Redirect", method=RequestMethod.GET)
	public void initSSORequestRedirect(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws Exception {
		final AuthnRequest authnRequest = buildAuthnRequest(servletRequest);
		authnRequest.setDestination(getDestinationRedirect(servletRequest, "SSO"));
		final Endpoint endpoint = buildIdpSsoEndpoint(SAMLConstants.SAML2_REDIRECT_BINDING_URI, authnRequest.getDestination());
        final String spEntityID = getSpEntityId(servletRequest);
		final String idpEntityID = getIdpEntityId(servletRequest);
		final MessageContext messageContext = buildOutboundMessageContext(authnRequest, endpoint, spEntityID, idpEntityID);
		encodeOutboundMessageContextRedirect(messageContext, servletResponse);
	}

	@RequestMapping(value="/InitSSO/POST", method=RequestMethod.GET)
	public void initSSORequestPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws Exception {
	    final AuthnRequest authnRequest = buildAuthnRequest(servletRequest);
		authnRequest.setDestination(getDestinationPost(servletRequest, "SSO"));
		final Endpoint endpoint = buildIdpSsoEndpoint(SAMLConstants.SAML2_POST_BINDING_URI, authnRequest.getDestination());
        final String spEntityID = getSpEntityId(servletRequest);
        final String idpEntityID = getIdpEntityId(servletRequest);
        final MessageContext messageContext = buildOutboundMessageContext(authnRequest, endpoint, spEntityID, idpEntityID);
		SAMLMessageSecuritySupport.signMessage(messageContext);
		encodeOutboundMessageContextPost(messageContext, servletResponse);
	}

   @RequestMapping(value="/InitSSO/Artifact", method=RequestMethod.GET)
    public void initSSORequestArtifact(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws Exception {
        final AuthnRequest authnRequest = buildAuthnRequest(servletRequest);
        authnRequest.setDestination(getDestinationArtifact(servletRequest, "SSO"));
        final Endpoint endpoint = buildIdpSsoEndpoint(SAMLConstants.SAML2_ARTIFACT_BINDING_URI, authnRequest.getDestination());
        final String spEntityID = getSpEntityId(servletRequest);
        final String idpEntityID = getIdpEntityId(servletRequest);
        final MessageContext messageContext = buildOutboundMessageContext(authnRequest, endpoint, spEntityID, idpEntityID);
        encodeOutboundMessageContextArtifact(messageContext, servletResponse);
    }

    @RequestMapping(value="/InitSSO/Passive", method=RequestMethod.GET)
    public void initSSORequestPassive(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws Exception {
        final AuthnRequest authnRequest = buildAuthnRequest(servletRequest);
        authnRequest.setDestination(getDestinationRedirect(servletRequest, "SSO"));
        authnRequest.setIsPassive(true);
        final Endpoint endpoint = buildIdpSsoEndpoint(SAMLConstants.SAML2_REDIRECT_BINDING_URI, authnRequest.getDestination());
        final String spEntityID = getSpEntityId(servletRequest);
        final String idpEntityID = getIdpEntityId(servletRequest);
        final MessageContext messageContext = buildOutboundMessageContext(authnRequest, endpoint, spEntityID, idpEntityID);
        encodeOutboundMessageContextRedirect(messageContext, servletResponse);
    }

    @RequestMapping(value="/InitSSO/ForceAuthn", method=RequestMethod.GET)
    public void initSSORequestForceAuthn(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws Exception {
        final AuthnRequest authnRequest = buildAuthnRequest(servletRequest);
        authnRequest.setDestination(getDestinationRedirect(servletRequest, "SSO"));
        authnRequest.setForceAuthn(true);
        final Endpoint endpoint = buildIdpSsoEndpoint(SAMLConstants.SAML2_REDIRECT_BINDING_URI, authnRequest.getDestination());
        final String spEntityID = getSpEntityId(servletRequest);
        final String idpEntityID = getIdpEntityId(servletRequest);
        final MessageContext messageContext = buildOutboundMessageContext(authnRequest, endpoint, spEntityID, idpEntityID);
        encodeOutboundMessageContextRedirect(messageContext, servletResponse);
    }
    
    @RequestMapping(value="/InitSSO/ReqAttr", method=RequestMethod.GET)
    public void initSSORequestReqAttr(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws Exception {
        final AuthnRequest authnRequest = buildAuthnRequest(servletRequest);
        authnRequest.setExtensions(buildRequestedAttributesExtensions());
        authnRequest.setDestination(getDestinationRedirect(servletRequest, "SSO"));
        final Endpoint endpoint = buildIdpSsoEndpoint(SAMLConstants.SAML2_REDIRECT_BINDING_URI, authnRequest.getDestination());
        final String spEntityID = getSpEntityId(servletRequest);
        final String idpEntityID = getIdpEntityId(servletRequest);
        final MessageContext messageContext = buildOutboundMessageContext(authnRequest, endpoint, spEntityID, idpEntityID);
        encodeOutboundMessageContextRedirect(messageContext, servletResponse);
    }

    @RequestMapping(value = "/InitSSO/POST/Passive", method = RequestMethod.GET) public void initSSORequestPostPassive(
            HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws Exception {
        final AuthnRequest authnRequest = buildAuthnRequest(servletRequest);
        authnRequest.setDestination(getDestinationPost(servletRequest, "SSO"));
        authnRequest.setIsPassive(true);
        final Endpoint endpoint = buildIdpSsoEndpoint(SAMLConstants.SAML2_POST_BINDING_URI, authnRequest.getDestination());
        final String spEntityID = getSpEntityId(servletRequest);
        final String idpEntityID = getIdpEntityId(servletRequest);
        final MessageContext messageContext = buildOutboundMessageContext(authnRequest, endpoint, spEntityID, idpEntityID);
        SAMLMessageSecuritySupport.signMessage(messageContext);
        encodeOutboundMessageContextPost(messageContext, servletResponse);
    }
    
    @RequestMapping(value = "/InitSSO/POST/ForceAuthn", method = RequestMethod.GET) public void
            initSSORequestPostForceAuthn(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
                    throws Exception {
        final AuthnRequest authnRequest = buildAuthnRequest(servletRequest);
        authnRequest.setDestination(getDestinationPost(servletRequest, "SSO"));
        authnRequest.setForceAuthn(true);
        final Endpoint endpoint = buildIdpSsoEndpoint(SAMLConstants.SAML2_POST_BINDING_URI, authnRequest.getDestination());
        final String spEntityID = getSpEntityId(servletRequest);
        final String idpEntityID = getIdpEntityId(servletRequest);
        final MessageContext messageContext = buildOutboundMessageContext(authnRequest, endpoint, spEntityID, idpEntityID);

        SAMLMessageSecuritySupport.signMessage(messageContext);
        encodeOutboundMessageContextPost(messageContext, servletResponse);
    }
    
    @RequestMapping(value="/InitSLO/Redirect", method=RequestMethod.GET)
    public void initSLORequestRedirect(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws Exception {
        final LogoutRequest logoutRequest = buildLogoutRequest(servletRequest, servletRequest.getParameter("transientID"));
        logoutRequest.setDestination(getDestinationRedirect(servletRequest, "SLO"));
        final Endpoint endpoint = buildIdpSsoEndpoint(SAMLConstants.SAML2_REDIRECT_BINDING_URI, logoutRequest.getDestination());
        final String spEntityID = getSpEntityId(servletRequest);
        final String idpEntityID = getIdpEntityId(servletRequest);
        final MessageContext messageContext = buildOutboundMessageContext(logoutRequest, endpoint, spEntityID, idpEntityID);
        encodeOutboundMessageContextRedirect(messageContext, servletResponse);
    }

    @RequestMapping(value="/InitSLO/Async", method=RequestMethod.GET)
    public void initSLORequestAsync(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws Exception {
        final LogoutRequest logoutRequest = buildLogoutRequest(servletRequest, servletRequest.getParameter("transientID"));
        logoutRequest.setDestination(getDestinationRedirect(servletRequest, "SLO"));
        
        final Extensions exts = (Extensions) builderFactory.getBuilder(Extensions.DEFAULT_ELEMENT_NAME)
                .buildObject(Extensions.DEFAULT_ELEMENT_NAME);
        logoutRequest.setExtensions(exts);
        exts.getUnknownXMLObjects().add(
                builderFactory.getBuilder(Asynchronous.DEFAULT_ELEMENT_NAME).buildObject(Asynchronous.DEFAULT_ELEMENT_NAME));
        
        final Endpoint endpoint = buildIdpSloEndpoint(SAMLConstants.SAML2_REDIRECT_BINDING_URI, logoutRequest.getDestination());
        final String spEntityID = getSpEntityId(servletRequest);
        final String idpEntityID = getIdpEntityId(servletRequest);
        final MessageContext messageContext = buildOutboundMessageContext(logoutRequest, endpoint, spEntityID, idpEntityID);
        encodeOutboundMessageContextRedirect(messageContext, servletResponse);
    }
    
    @RequestMapping(value="/InitSLO/POST", method=RequestMethod.GET)
    public void initSLORequestPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws Exception {
        final LogoutRequest logoutRequest = buildLogoutRequest(servletRequest, servletRequest.getParameter("transientID"));
        logoutRequest.setDestination(getDestinationPost(servletRequest, "SLO"));
        final Endpoint endpoint = buildIdpSloEndpoint(SAMLConstants.SAML2_POST_BINDING_URI, logoutRequest.getDestination());
        final String spEntityID = getSpEntityId(servletRequest);
        final String idpEntityID = getIdpEntityId(servletRequest);
        final MessageContext messageContext = buildOutboundMessageContext(logoutRequest, endpoint, spEntityID, idpEntityID);
        SAMLMessageSecuritySupport.signMessage(messageContext);
        encodeOutboundMessageContextPost(messageContext, servletResponse);
    }

    @RequestMapping(value="/FinishSLO/Redirect", method=RequestMethod.GET)
    public void finishSLOResponseRedirect(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws Exception {
        final LogoutResponse logoutResponse = buildLogoutResponse(servletRequest);
        logoutResponse.setDestination(getDestinationRedirect(servletRequest, "SLO"));
        final Endpoint endpoint = buildIdpSloEndpoint(SAMLConstants.SAML2_REDIRECT_BINDING_URI, logoutResponse.getDestination());
        final String spEntityID = getSpEntityId(servletRequest);
        final String idpEntityID = getIdpEntityId(servletRequest);
        final MessageContext messageContext = buildOutboundMessageContext(logoutResponse, endpoint, spEntityID, idpEntityID);
        encodeOutboundMessageContextRedirect(messageContext, servletResponse);
    }

    @RequestMapping(value="/FinishSLO/POST", method=RequestMethod.GET)
    public void finishSLOResponsePost(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws Exception {
        final LogoutResponse logoutResponse = buildLogoutResponse(servletRequest);
        logoutResponse.setDestination(getDestinationPost(servletRequest, "SLO"));
        final Endpoint endpoint = buildIdpSloEndpoint(SAMLConstants.SAML2_POST_BINDING_URI, logoutResponse.getDestination());
        final String spEntityID = getSpEntityId(servletRequest);
        final String idpEntityID = getIdpEntityId(servletRequest);
        final MessageContext messageContext = buildOutboundMessageContext(logoutResponse, endpoint, spEntityID, idpEntityID);
        SAMLMessageSecuritySupport.signMessage(messageContext);
        encodeOutboundMessageContextPost(messageContext, servletResponse);
    }

    @RequestMapping(value="/FinishSLO/SOAP", method=RequestMethod.GET)
    public void finishSLOResponseSOAP(HttpServletRequest servletRequest, HttpServletResponse servletResponse, final String id) throws Exception {
        final LogoutResponse logoutResponse = buildLogoutResponse(servletRequest);
        logoutResponse.setInResponseTo(id);
        final String spEntityID = getSpEntityId(servletRequest);
        final String idpEntityID = getIdpEntityId(servletRequest);
        final MessageContext messageContext = buildOutboundMessageContext(logoutResponse, null, spEntityID, idpEntityID);
        SAMLMessageSecuritySupport.signMessage(messageContext);
        encodeOutboundMessageContextSOAP(messageContext, servletResponse);
    }
    
	@RequestMapping(value="/POST/ACS", method=RequestMethod.POST)
	public ResponseEntity<String> handleSSOResponsePOST(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws Exception {
		final MessageContext messageContext = decodeInboundMessageContextPost(servletRequest);
		
		if (!(messageContext.getMessage() instanceof Response)) {
			log.error("Inbound message was not a SAML 2 Response");
			return new ResponseEntity<>("Inbound message was not a SAML 2 Response", HttpStatus.BAD_REQUEST);
		}
		
		final Response response = (Response) messageContext.getMessage();
		final Element responseElement = response.getDOM();
		final String formattedMessage = SerializeSupport.prettyPrintXML(responseElement);
        log.trace("Returning response" + System.lineSeparator() + "{}", formattedMessage);
		
		//TODO instead of returning plain text via a ResponseEntity, add a JSP view that looks good
		
		final HttpHeaders headers = new HttpHeaders();
		headers.add("Content-Type", "text/plain");
		
		return new ResponseEntity<>(formattedMessage, headers, HttpStatus.OK);
	}

    @RequestMapping(value="/Redirect/SLO", method=RequestMethod.GET)
    public ResponseEntity<String> handleSLOResponseRedirect(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws Exception {
        final MessageContext messageContext = decodeInboundMessageContextRedirect(servletRequest);
        
        if (messageContext.getMessage() instanceof LogoutRequest) {
            servletRequest.setAttribute("success", "1");
            finishSLOResponseRedirect(servletRequest, servletResponse);
            return null;
        }
        
        final LogoutResponse response = (LogoutResponse) messageContext.getMessage();
        final Element responseElement = response.getDOM();
        final String formattedMessage = SerializeSupport.prettyPrintXML(responseElement);
        
        //TODO instead of returning plain text via a ResponseEntity, add a JSP view that looks good
        
        final HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "text/plain");
        
        return new ResponseEntity<>(formattedMessage, headers, HttpStatus.OK);
    }
	
    @RequestMapping(value="/POST/SLO", method=RequestMethod.POST)
    public ResponseEntity<String> handleSLOResponsePOST(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws Exception {
        final MessageContext messageContext = decodeInboundMessageContextPost(servletRequest);
        
        if (messageContext.getMessage() instanceof LogoutRequest) {
            servletRequest.setAttribute("success", "1");
            finishSLOResponsePost(servletRequest, servletResponse);
            return null;
        }
        
        final LogoutResponse response = (LogoutResponse) messageContext.getMessage();
        final Element responseElement = response.getDOM();
        final String formattedMessage = SerializeSupport.prettyPrintXML(responseElement);
        
        //TODO instead of returning plain text via a ResponseEntity, add a JSP view that looks good
        
        final HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "text/plain");
        
        return new ResponseEntity<>(formattedMessage, headers, HttpStatus.OK);
    }
    
    @RequestMapping(value="/SOAP/SLO", method=RequestMethod.POST)
    public ResponseEntity<String> handleSLOResponseSOAP(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws Exception {
        final MessageContext messageContext = decodeInboundMessageContextSOAP(servletRequest);
        
        if (messageContext.getMessage() instanceof LogoutRequest) {
            servletRequest.setAttribute("success", "1");
            finishSLOResponseSOAP(servletRequest, servletResponse, ((LogoutRequest) messageContext.getMessage()).getID());
            return null;
        }
        
        final XMLObject msg = (XMLObject) messageContext.getMessage();
        final Element responseElement = msg.getDOM();
        final String formattedMessage = SerializeSupport.prettyPrintXML(responseElement);
        
        //TODO instead of returning plain text via a ResponseEntity, add a JSP view that looks good
        
        final HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "text/plain");
        
        return new ResponseEntity<>(formattedMessage, headers, HttpStatus.OK);
    }

    private MessageContext buildOutboundMessageContext(SAMLObject message, Endpoint endpoint, String spEntityId, String idpEntityId) {
		final MessageContext messageContext = new MessageContext();
		messageContext.setMessage(message);

	    SAMLSelfEntityContext selfContext = messageContext.getSubcontext(SAMLSelfEntityContext.class, true);
	    selfContext.setEntityId(spEntityId);

		SAMLPeerEntityContext peerContext = messageContext.getSubcontext(SAMLPeerEntityContext.class, true);
		peerContext.setEntityId(idpEntityId);
		
		if (endpoint != null) {
		    SAMLEndpointContext endpointContext = peerContext.getSubcontext(SAMLEndpointContext.class, true);
		    endpointContext.setEndpoint(endpoint);
		}
		
		SAMLArtifactContext artifactContext = messageContext.getSubcontext(SAMLArtifactContext.class, true);
		artifactContext.setSourceArtifactResolutionServiceEndpointIndex(1);
		
		SignatureSigningParameters signingParameters = new SignatureSigningParameters();
		signingParameters.setSigningCredential(spCredential);
		signingParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		//signingParameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
		signingParameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		SecurityParametersContext secParamsContext = messageContext.getSubcontext(SecurityParametersContext.class, true);
		secParamsContext.setSignatureSigningParameters(signingParameters);
		
		return messageContext;
	}

    private void setupResponse(final AbstractHttpServletResponseMessageEncoder encoder, final HttpServletResponse response) {
        encoder.setHttpServletResponseSupplier(new Supplier() {
            public HttpServletResponse get() {
                return response;
            }
        });
    }

	private void encodeOutboundMessageContextRedirect(MessageContext messageContext, HttpServletResponse servletResponse) throws Exception {
		HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
		try {
		    setupResponse(encoder,servletResponse);
			encoder.setMessageContext(messageContext);
			encoder.initialize();
			
			encoder.prepareContext();
			encoder.encode();
		} catch (final ComponentInitializationException | MessageEncodingException e) {
			log.error("Error encoding the outbound message context", e);
			throw e;
		} finally {
			encoder.destroy();
		}
	}
	
	private void encodeOutboundMessageContextPost(MessageContext messageContext, HttpServletResponse servletResponse) throws Exception {
		HTTPPostEncoder encoder = new HTTPPostEncoder();
		try {
		    setupResponse(encoder,servletResponse);
			encoder.setMessageContext(messageContext);
			encoder.setVelocityEngine(velocityEngine);
			encoder.initialize();
			
			encoder.prepareContext();
			encoder.encode();
		} catch (final ComponentInitializationException | MessageEncodingException e) {
			log.error("Error encoding the outbound message context", e);
			throw e;
		} finally {
			encoder.destroy();
		}
	}

   private void encodeOutboundMessageContextArtifact(MessageContext messageContext, HttpServletResponse servletResponse) throws Exception {
        HTTPArtifactEncoder encoder = new HTTPArtifactEncoder();
        try {
            setupResponse(encoder,servletResponse);
            encoder.setMessageContext(messageContext);
            encoder.setVelocityEngine(velocityEngine);
            encoder.setArtifactMap(artifactMap);
            encoder.initialize();
            
            encoder.prepareContext();
            encoder.encode();
        } catch (final ComponentInitializationException | MessageEncodingException e) {
            log.error("Error encoding the outbound message context", e);
            throw e;
        } finally {
            encoder.destroy();
        }
    }
   
   private void encodeOutboundMessageContextSOAP(MessageContext messageContext, HttpServletResponse servletResponse) throws Exception {
       HTTPSOAP11Encoder encoder = new HTTPSOAP11Encoder();
       try {
           setupResponse(encoder,servletResponse);
           encoder.setMessageContext(messageContext);
           encoder.initialize();
           
           encoder.prepareContext();
           encoder.encode();
       } catch (final ComponentInitializationException | MessageEncodingException e) {
           log.error("Error encoding the outbound message context", e);
           throw e;
       } finally {
           encoder.destroy();
       }
   }

	private SingleSignOnService buildIdpSsoEndpoint(String binding, String destination) {
		final SingleSignOnService ssoEndpoint = (SingleSignOnService) builderFactory.getBuilder(
		        SingleSignOnService.DEFAULT_ELEMENT_NAME).buildObject(SingleSignOnService.DEFAULT_ELEMENT_NAME);
		ssoEndpoint.setBinding(binding);
		ssoEndpoint.setLocation(destination);
		return ssoEndpoint;
	}

    private SingleLogoutService buildIdpSloEndpoint(String binding, String destination) {
        final SingleLogoutService sloEndpoint = (SingleLogoutService) builderFactory.getBuilder(
                SingleLogoutService.DEFAULT_ELEMENT_NAME).buildObject(SingleLogoutService.DEFAULT_ELEMENT_NAME);
        sloEndpoint.setBinding(binding);
        sloEndpoint.setLocation(destination);
        return sloEndpoint;
    }
	
	private AuthnRequest buildAuthnRequest(HttpServletRequest servletRequest) {
		final AuthnRequest authnRequest = (AuthnRequest) builderFactory.getBuilder(
		        AuthnRequest.DEFAULT_ELEMENT_NAME).buildObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
		
		authnRequest.setID(idGenerator.generateIdentifier());
		authnRequest.setIssueInstant(Instant.now());
		authnRequest.setAssertionConsumerServiceURL(getAcsUrl(servletRequest));
		authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
		
		final Issuer issuer = (Issuer) builderFactory.getBuilder(
		        Issuer.DEFAULT_ELEMENT_NAME).buildObject(Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(getSpEntityId(servletRequest));
		authnRequest.setIssuer(issuer);
		
		final NameIDPolicy nameIDPolicy = (NameIDPolicy) builderFactory.getBuilder(
		        NameIDPolicy.DEFAULT_ELEMENT_NAME).buildObject(NameIDPolicy.DEFAULT_ELEMENT_NAME);
		nameIDPolicy.setAllowCreate(true);
		authnRequest.setNameIDPolicy(nameIDPolicy);
		
		String param = StringSupport.trimOrNull(servletRequest.getParameter("nameIDFormat"));
		if (param != null) {
		    nameIDPolicy.setFormat(param);
		}
		
		param = StringSupport.trimOrNull(servletRequest.getParameter("spNameQualifier"));
		if (param != null) {
		    nameIDPolicy.setSPNameQualifier(param);
		}

		param = StringSupport.trimOrNull(servletRequest.getParameter("subjectID"));
		if (param != null) {
	        final NameID nameID = (NameID) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME).buildObject(NameID.DEFAULT_ELEMENT_NAME);
	        nameID.setValue(param);
	        param = StringSupport.trimOrNull(servletRequest.getParameter("subjectIDFormat"));
	        if (param != null) {
	            nameID.setFormat(param);
	        }
            final Subject subject = (Subject) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME).buildObject(Subject.DEFAULT_ELEMENT_NAME);
	        subject.setNameID(nameID);
            authnRequest.setSubject(subject);
		}
		
		param = StringSupport.trimOrNull(servletRequest.getParameter("classRef"));
		if (param != null) {
            final AuthnContextClassRef ref = (AuthnContextClassRef) builderFactory.getBuilder(
                    AuthnContextClassRef.DEFAULT_ELEMENT_NAME).buildObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
            ref.setURI(param);
	        final RequestedAuthnContext rac = (RequestedAuthnContext) builderFactory.getBuilder(
	                RequestedAuthnContext.DEFAULT_ELEMENT_NAME).buildObject(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
	        rac.getAuthnContextClassRefs().add(ref);
	        authnRequest.setRequestedAuthnContext(rac);
		}
		
		param = StringSupport.trimOrNull(servletRequest.getParameter("requesters"));
		if (param != null) {
		    final String[] requesters = param.split(",");
		    if (requesters != null && requesters.length > 0) {
	            for (final String req : requesters) {
	                final RequesterID requesterID = (RequesterID) builderFactory.getBuilder(
	                        RequesterID.DEFAULT_ELEMENT_NAME).buildObject(RequesterID.DEFAULT_ELEMENT_NAME);
	                requesterID.setURI(req);
	                getScoping(authnRequest).getRequesterIDs().add(requesterID);
	            }
		    }
		}
		
        param = StringSupport.trimOrNull(servletRequest.getParameter("idplist"));
        if (param != null) {
            final String[] idplist = param.split(",");
            if (idplist != null && idplist.length > 0) {
                final IDPList obj = (IDPList) builderFactory.getBuilder(
                        IDPList.DEFAULT_ELEMENT_NAME).buildObject(IDPList.DEFAULT_ELEMENT_NAME);
                for (final String idp : idplist) {
                    final IDPEntry entry = (IDPEntry) builderFactory.getBuilder(
                            IDPEntry.DEFAULT_ELEMENT_NAME).buildObject(IDPEntry.DEFAULT_ELEMENT_NAME);
                    entry.setProviderID(idp);
                    obj.getIDPEntrys().add(entry);
                }
                getScoping(authnRequest).setIDPList(obj);
            }
        }

        param = StringSupport.trimOrNull(servletRequest.getParameter("proxycount"));
        if (param != null) {
            getScoping(authnRequest).setProxyCount(Integer.valueOf(param));
        }
        
		return authnRequest;
	}
	
	private Scoping getScoping(@Nonnull final AuthnRequest request) {
	    if (request.getScoping() == null) {
            final Scoping scoping = (Scoping) builderFactory.getBuilder(
                    Scoping.DEFAULT_ELEMENT_NAME).buildObject(Scoping.DEFAULT_ELEMENT_NAME);
            request.setScoping(scoping);
	    }
	    
	    return request.getScoping();
	}

    private Extensions buildRequestedAttributesExtensions()
    {
        final RequestedAttribute attribute = (RequestedAttribute) builderFactory.getBuilder(
                RequestedAttribute.DEFAULT_ELEMENT_NAME).buildObject(RequestedAttribute.DEFAULT_ELEMENT_NAME);
        attribute.setFriendlyName("mail");
        attribute.setName("urn:oid:0.9.2342.19200300.100.1.3");
        attribute.setNameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
        final RequestedAttributes attributes = (RequestedAttributes) builderFactory.getBuilder(
                RequestedAttributes.DEFAULT_ELEMENT_NAME).buildObject(RequestedAttributes.DEFAULT_ELEMENT_NAME);
        attributes.getRequestedAttributes().add(attribute);
        final Extensions extensions = (Extensions) builderFactory.getBuilder(
                Extensions.DEFAULT_ELEMENT_NAME).buildObject(Extensions.DEFAULT_ELEMENT_NAME);
        extensions.getUnknownXMLObjects().add(attributes);
       return extensions;
    }

    private LogoutRequest buildLogoutRequest(HttpServletRequest servletRequest, String principalName) {
        final LogoutRequest logoutRequest = (LogoutRequest) builderFactory.getBuilder(
                LogoutRequest.DEFAULT_ELEMENT_NAME).buildObject(LogoutRequest.DEFAULT_ELEMENT_NAME);
        
        logoutRequest.setID(idGenerator.generateIdentifier());
        logoutRequest.setIssueInstant(Instant.now());
        
        final Issuer issuer = (Issuer) builderFactory.getBuilder(
                Issuer.DEFAULT_ELEMENT_NAME).buildObject(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(getSpEntityId(servletRequest));
        logoutRequest.setIssuer(issuer);
        
        final NameID nameID = (NameID) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME).buildObject(NameID.DEFAULT_ELEMENT_NAME);
        nameID.setValue(principalName);
        nameID.setFormat(NameID.TRANSIENT);
        nameID.setSPNameQualifier(getSpEntityId(servletRequest));
        nameID.setNameQualifier(getIdpEntityId(servletRequest));
        logoutRequest.setNameID(nameID);
        
        return logoutRequest;
    }

    private LogoutResponse buildLogoutResponse(HttpServletRequest servletRequest) {
        final LogoutResponse logoutResponse = (LogoutResponse) builderFactory.getBuilder(
                LogoutResponse.DEFAULT_ELEMENT_NAME).buildObject(LogoutResponse.DEFAULT_ELEMENT_NAME);
        
        logoutResponse.setID(idGenerator.generateIdentifier());
        logoutResponse.setIssueInstant(Instant.now());
        
        final Issuer issuer = (Issuer) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME).buildObject(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(getSpEntityId(servletRequest));
        logoutResponse.setIssuer(issuer);
        
        final Status status = (Status) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME).buildObject(Status.DEFAULT_ELEMENT_NAME);
        logoutResponse.setStatus(status);
        
        final StatusCode code = (StatusCode) builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME).buildObject(StatusCode.DEFAULT_ELEMENT_NAME);
        status.setStatusCode(code);
        String param = servletRequest.getParameter("success");
        if (param == null) {
            final Object attr = servletRequest.getAttribute("success");
            if (attr != null) {
                param = (String) attr;
            }
        }
        
        if (param != null && "1".equals(param)) {
            code.setValue(StatusCode.SUCCESS);
        } else {
            code.setValue(StatusCode.RESPONDER);
        }
        
        return logoutResponse;
    }
    
	private String getDestinationRedirect(HttpServletRequest servletRequest, String profile) {
		//TODO servlet context
		String destinationPath = "/idp/profile/SAML2/Redirect/" + profile;
		String baseUrl = getBaseUrl(servletRequest);
		try {
			URLBuilder urlBuilder = new URLBuilder(baseUrl);
			urlBuilder.setPath(destinationPath);
			return urlBuilder.buildURL();
		} catch (MalformedURLException e) {
			log.error("Couldn't parse base URL, reverting to internal default destination: {}", baseUrl);
			return "http://localhost:8080" + destinationPath;
		}
	}
	
	private String getDestinationPost(HttpServletRequest servletRequest, String profile) {
		//TODO servlet context
		String destinationPath = "/idp/profile/SAML2/POST/" + profile;
		String baseUrl = getBaseUrl(servletRequest);
		try {
			URLBuilder urlBuilder = new URLBuilder(baseUrl);
			urlBuilder.setPath(destinationPath);
			return urlBuilder.buildURL();
		} catch (MalformedURLException e) {
			log.error("Couldn't parse base URL, reverting to internal default destination: {}", baseUrl);
			return "http://localhost:8080" + destinationPath;
		}
	}

	private String getDestinationArtifact(HttpServletRequest servletRequest, String profile) {
        //TODO servlet context
        String destinationPath = "/idp/profile/SAML2/Artifact/" + profile;
        String baseUrl = getBaseUrl(servletRequest);
        try {
            URLBuilder urlBuilder = new URLBuilder(baseUrl);
            urlBuilder.setPath(destinationPath);
            return urlBuilder.buildURL();
        } catch (MalformedURLException e) {
            log.error("Couldn't parse base URL, reverting to internal default destination: {}", baseUrl);
            return "http://localhost:8080" + destinationPath;
        }
    }

	private String getAcsUrl(HttpServletRequest servletRequest) {
		//TODO servlet context
	    String spId = getSpId(servletRequest);
        String acsPath = (spId == null) ? "/sp/SAML2/POST/ACS" : "/sp/" + spId + "/SAML2/POST/ACS";
		String baseUrl = getBaseUrl(servletRequest);
		try {
			URLBuilder urlBuilder = new URLBuilder(baseUrl);
			urlBuilder.setPath(acsPath);
			return urlBuilder.buildURL();
		} catch (MalformedURLException e) {
			log.error("Couldn't parse base URL, reverting to internal default ACS: {}", baseUrl);
			return "http://localhost:8080" + acsPath;
		}
	}
	
	private String getBaseUrl(HttpServletRequest servletRequest) {
		//TODO servlet context
		String requestUrl = servletRequest.getRequestURL().toString();
		try {
			URLBuilder urlBuilder = new URLBuilder(requestUrl);
			urlBuilder.setUsername(null);
			urlBuilder.setPassword(null);
			urlBuilder.setPath(null);
			urlBuilder.getQueryParams().clear();
			urlBuilder.setFragment(null);
			return urlBuilder.buildURL();
		} catch (MalformedURLException e) {
			log.error("Couldn't parse request URL, reverting to internal default base URL: {}", requestUrl);
			return "http://localhost:8080";
		}
		
	}

    private String getSpEntityId(HttpServletRequest servletRequest) {
        // TODO get from config somewhere
        final String spId = getSpId(servletRequest);
        return (spId == null) ? "https://sp.example.org" : "https://" + spId + ".example.org";
    }

    private String getIdpEntityId(HttpServletRequest servletRequest) {
        // TODO get from config somewhere
        // Sometimes it's useful to return an IdP entityID per SP.
        // final String spId = getSpId(servletRequest);
        // return (spId == null) ? "https://idp.example.org" : "https://idp." + spId + ".example.org";
        return "https://idp.example.org";
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

    @RequestMapping(method = RequestMethod.GET) public ResponseEntity<String>
            defaultPage(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws Exception {
        final StringBuilder builder = new StringBuilder();
        builder.append("SP id = " + getSpId(servletRequest) + "\n");
        builder.append("SP entityID = " + getSpEntityId(servletRequest) + "\n");
        builder.append("SP credential entityID = " + spCredential.getEntityId() + "\n");
        builder.append("IdP entityID = " + getIdpEntityId(servletRequest) + "\n");
        final String formattedMessage = builder.toString();
        final HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "text/plain");
        return new ResponseEntity<>(formattedMessage, headers, HttpStatus.OK);
    }
    
    /**
     * Send a SAML 2 logout request.
     * 
     * @param servletRequest the servlet request
     * @param servletResponse the servlet response
     * @param endpoint the endpoint to send the logout request to
     * @param principalName the name of the principal to logout
     * @param trustedTLSCertificate the trusted IdP public certificate
     * @param trustedTLSCertificatePassword the IdP certificate password
     * @param clientTLSCertificate the SP public certificate
     * @param clientTLSPrivateKey the SP private key
     * @param clientTLSPassword the SP password
     * @param clientSigningCertificate ...
     * @param clientSigningPrivateKey ...
     * 
     * @return the SAML 2 logout response is displayed
     * 
     * @throws Exception if an error occurs
     */
    @RequestMapping(value = "/InitSLO/SOAP", method = RequestMethod.POST) public ResponseEntity<String>
            initSAML2LogoutRequest(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
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

        final LogoutRequest logoutRequest = buildLogoutRequest(servletRequest, principalName);

        // Sign if client signing certificate is present
        if (StringSupport.trimOrNull(clientSigningCertificate) != null) {
            sign(logoutRequest, clientSigningCertificate, clientSigningPrivateKey);
        }

        final Envelope envelope = buildSOAP11Envelope(logoutRequest);

        if (log.isDebugEnabled()) {
            log.debug("Sending LogoutRequest to endpoint '{}':\n", endpoint, SerializeSupport.prettyPrintXML(
                    marshallerFactory.getMarshaller(envelope).marshall(envelope, parserPool.newDocument())));
        }

        final InOutOperationContext context = buildInOutOperationContext(envelope);

        httpSoapClient.send(endpoint, context);

        final Envelope soapResponse =
                context.getInboundMessageContext().getSubcontext(SOAP11Context.class).getEnvelope();

        final String formattedMessage = SerializeSupport.prettyPrintXML(soapResponse.getDOM());

        final HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "text/plain");

        return new ResponseEntity<>(formattedMessage, headers, HttpStatus.OK);
    }    

    /**
     * Send a SAML 2 attribute query.
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
     * @return the SAML 2 attribute query response is displayed
     * 
     * @throws Exception if an error occurs
     */
    @RequestMapping(value = "/AttributeQuery", method = RequestMethod.POST) public ResponseEntity<String>
            initSAML2AttributeQuery(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
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

        final AttributeQuery attributeQuery = buildSAML2AttributeQueryRequest(servletRequest, principalName);

        // Sign if client signing certificate is present
        if (StringSupport.trimOrNull(clientSigningCertificate) != null) {
            sign(attributeQuery, clientSigningCertificate, clientSigningPrivateKey);
        }

        final Envelope envelope = buildSOAP11Envelope(attributeQuery);

        if (log.isDebugEnabled()) {
            log.debug("Sending AttributeQuery to endpoint '{}':\n", endpoint, SerializeSupport.prettyPrintXML(
                    marshallerFactory.getMarshaller(envelope).marshall(envelope, parserPool.newDocument())));
        }

        final InOutOperationContext context = buildInOutOperationContext(envelope);

        httpSoapClient.send(endpoint, context);

        final Envelope soapResponse =
                context.getInboundMessageContext().getSubcontext(SOAP11Context.class).getEnvelope();

        final String formattedMessage = SerializeSupport.prettyPrintXML(soapResponse.getDOM());

        final HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "text/plain");

        return new ResponseEntity<>(formattedMessage, headers, HttpStatus.OK);
    }

    /**
     * Builds a basic SAML 2 attribute query.
     * 
     * @param servletRequest ...
     * @param principalName the principal name
     * 
     * @return the attribute query
     */
    @Nonnull public AttributeQuery buildSAML2AttributeQueryRequest(@Nonnull final HttpServletRequest servletRequest,
            @Nonnull final String principalName) {

        final Subject subject = buildSubject(principalName);

        final AttributeQuery attributeQuery = buildAttributeQueryRequest(subject);
        attributeQuery.setIssueInstant(Instant.now());
        attributeQuery.setID(new SecureRandomIdentifierGenerationStrategy().generateIdentifier());
        attributeQuery.setIssuer(buildIssuer(getSpEntityId(servletRequest)));

        // TODO AttributeDesignator

        return attributeQuery;
    }

    /**
     * Builds a {@link Issuer}.
     * 
     * @param entityID the entity ID to use in the Issuer
     * 
     * @return the built Issuer
     */
    @Nonnull public static Issuer buildIssuer(final @Nonnull @NotEmpty String entityID) {
        final SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().<Issuer>getBuilderOrThrow(
                        Issuer.DEFAULT_ELEMENT_NAME);
        final Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(entityID);
        return issuer;
    }
    
    /**
     * Builds a {@link Subject}. If a principal name is given a {@link NameID}, whose value is the given principal name,
     * will be created and added to the {@link Subject}.
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
            subject.setNameID(buildNameID(principalName));
        }

        return subject;
    }

    /**
     * Builds a {@link NameID}.
     * 
     * @param principalName the principal name to use in the NameID
     * 
     * @return the built NameID
     */
    @Nonnull public static NameID buildNameID(final @Nonnull @NotEmpty String principalName) {
        final SAMLObjectBuilder<NameID> nameIdBuilder = (SAMLObjectBuilder<NameID>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().<NameID>getBuilderOrThrow(
                        NameID.DEFAULT_ELEMENT_NAME);
        final NameID nameId = nameIdBuilder.buildObject();
        nameId.setValue(principalName);
        return nameId;
    }

    /**
     * Builds an {@link AttributeQuery}. If a {@link Subject} is given, it will be added to the constructed
     * {@link AttributeQuery}.
     * 
     * @param subject the subject to add to the query
     * 
     * @return the built query
     */
    @Nonnull public static AttributeQuery buildAttributeQueryRequest(final @Nullable Subject subject) {
        final SAMLObjectBuilder<AttributeQuery> queryBuilder = (SAMLObjectBuilder<AttributeQuery>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().<AttributeQuery>getBuilderOrThrow(
                        AttributeQuery.DEFAULT_ELEMENT_NAME);

        final AttributeQuery query = queryBuilder.buildObject();
        query.setIssueInstant(Instant.now());
        query.setVersion(SAMLVersion.VERSION_20);

        if (subject != null) {
            query.setSubject(subject);
        }

        return query;
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

    /**
     * Build a {@link InOutOperationContext}.
     * 
     * @param envelope the envelope
     * @return the context
     */
    @Nonnull public static InOutOperationContext buildInOutOperationContext(@Nonnull final Envelope envelope) {
        final SOAP11Context soap11Ctx = new SOAP11Context();
        soap11Ctx.setEnvelope(envelope);

        final MessageContext msgCtx = new MessageContext();
        msgCtx.addSubcontext(soap11Ctx);

        final InOutOperationContext inOutOpCtx = new InOutOperationContext() {};
        inOutOpCtx.setOutboundMessageContext(msgCtx);

        return inOutOpCtx;
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
