package controllers

import java.io._
import java.security.cert.{CertPathValidator, CertificateFactory, PKIXParameters, TrustAnchor, X509Certificate => JavaX509Certificate}
import java.security.{PrivateKey, Security}
import java.util.zip.GZIPOutputStream
import java.util.{Base64, UUID}
import javax.xml.namespace.QName
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult

import org.bouncycastle.openssl.PEMReader
import org.joda.time.DateTime
import org.opensaml.DefaultBootstrap
import org.opensaml.common.SAMLVersion
import org.opensaml.saml1.core.NameIdentifier
import org.opensaml.saml2.core._
import org.opensaml.saml2.core.impl._
import org.opensaml.saml2.metadata.EntityDescriptor
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider
import org.opensaml.security.SAMLSignatureProfileValidator
import org.opensaml.xml.parse.BasicParserPool
import org.opensaml.xml.schema.XSString
import org.opensaml.xml.schema.impl.XSStringBuilder
import org.opensaml.xml.security.x509.BasicX509Credential
import org.opensaml.xml.signature._
import org.opensaml.xml.{Configuration, XMLObject}
import org.w3c.dom.Document
import play.api.mvc.{Action, AnyContent, Controller, Request}
import play.api.Play._
import play.api.Logger

/**
  * Created by Philip Ogunleye 
  * © Copyright 2016 Ogunleye Enterprises. All rights reserved
  */

trait SAMLResponseController extends Controller {

  Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())
  DefaultBootstrap.bootstrap

  val documentBuilderFactory = DocumentBuilderFactory.newInstance()
  documentBuilderFactory.setNamespaceAware(true)

  def buildResponse = Action {
    implicit request =>
      Logger.info(s"Request recieved, processing")
      val entityID = loadConfig("saml.idp.entity")
      val requestID = request.body.asFormUrlEncoded.flatMap(_.get("requestID")).flatMap(_.headOption)
      val redirectURL = loadConfig("saml.idp.consumer")
      val user = extractParam("user")
      Logger.info(s"User $user sent in request")
      if(!requestID.isEmpty)
        Logger.info(s"RequestID ${requestID.get} provided")
      Ok(createSAMLResponse(entityID,redirectURL,requestID, user))
  }

  def loadMetadata(metadataPath: String, entityID: String): EntityDescriptor = {
    val metaDataProvider = new FilesystemMetadataProvider(new File(metadataPath))
    metaDataProvider.setRequireValidMetadata(true)
    metaDataProvider.setParserPool(new BasicParserPool())
    metaDataProvider.initialize()
    metaDataProvider.getEntityDescriptor(entityID)
  }

  private def loadConfig(key: String) = configuration.getString(key).getOrElse(throw new Exception(s"Missing key: $key"))

  private def signAndCompress(xml: XMLObject, signature: Signature): String = {
    val document = marshal(xml)
    Signer.signObject(signature)
    val validator = new SAMLSignatureProfileValidator
    val resp = xml.asInstanceOf[Response]
    validator.validate(resp.getSignature)
    validator.validate(resp.getAssertions.get(0).getSignature)
    Signer.signObject(resp.getAssertions.get(0).getSignature)
    val schemaValidator = Configuration.getValidatorSuite("saml2-core-schema-validator")
    schemaValidator.validate(xml)
    val specValidator = Configuration.getValidatorSuite("saml2-core-spec-validator");
    specValidator.validate(xml)
    val docWriter = new StringWriter
    TransformerFactory.newInstance.newTransformer.transform(new DOMSource(document), new StreamResult(docWriter))
    Logger.info("Response signed and written to XML")
    docWriter.toString
    //compressAndEncodeToB64(docWriter.toString)
  }

  private def marshal(xml: XMLObject): Document = {
    val responseMarshaller = Configuration.getMarshallerFactory().getMarshaller(xml)
    val document = documentBuilderFactory.newDocumentBuilder().newDocument()
    responseMarshaller.marshall(xml, document)
    document
  }

  private def compressAndEncodeToB64(saml: String): String = {
    Logger.info(s"Encoding and deflating SAML Response")
    Base64.getEncoder().encodeToString(deflate(saml))
  }

  private def deflate(uncompressed: String) = {
    val output = new ByteArrayOutputStream
    val zipOutStream = new GZIPOutputStream(output)
    zipOutStream.write(uncompressed.getBytes)
    zipOutStream.close
    output.toByteArray
  }

  private def signResponse(response : Response, signingCert : String, signingKey : String) = {
    val signature = createSignature(signingCert,signingKey)
    response.setSignature(signature)
    val assertionSignature = createSignature(signingCert,signingKey)
    response.getAssertions.get(0).setSignature(assertionSignature)
    Logger.info("Signature set on SAML response and Assertion")
    signAndCompress(response,signature)
  }

  private def createSignature(signingCert : String, signingKey : String) = {
    val signature = create[Signature](Signature.DEFAULT_ELEMENT_NAME)
    val keyInfo = create[KeyInfo](KeyInfo.DEFAULT_ELEMENT_NAME)
    val x509Data = create[X509Data](X509Data.DEFAULT_ELEMENT_NAME)
    val x509Certificate = create[X509Certificate](X509Certificate.DEFAULT_ELEMENT_NAME)
    val credential = createSigningCredential(signingCert, signingKey)
    signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512)
    signature.setSigningCredential(credential)
    signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
    signature.setKeyInfo(keyInfo)
    keyInfo.getX509Datas.add(x509Data)
    x509Data.getX509Certificates.add(x509Certificate)
    x509Certificate.setValue(Base64.getEncoder().encodeToString(credential.getEntityCertificate().getEncoded()))
    signature
  }

  private def createSigningCredential( signingCert: String, signingKey: String) : BasicX509Credential = {
    val credential = new BasicX509Credential()
    credential.setEntityCertificate(parseCertificate( signingCert ))
    val key = new PEMReader(new StringReader(signingKey.trim)).readObject().asInstanceOf[PrivateKey]
    credential.setPrivateKey(key)
    credential
  }

  private def parseCertificate( cert: String ): JavaX509Certificate = {
    val cf = CertificateFactory.getInstance("X.509")
    cf.generateCertificate(new ByteArrayInputStream(cert.trim.getBytes)).asInstanceOf[JavaX509Certificate]
  }

  private def createSAMLResponse(issuerID : String, returnAddress : String, requestID : Option[String], user : String) = {
    val response = create[Response](Response.DEFAULT_ELEMENT_NAME)
    val issuer = createIssuer(issuerID)
    response.getAssertions.add(createAssertion(issuer, user ,returnAddress, requestID))
    response.setIssuer(createIssuer(issuerID))
    response.setID(UUID.randomUUID.toString)
    response.setDestination(returnAddress)
    response.setIssueInstant(new DateTime())
    if(!requestID.isEmpty)
      response.setInResponseTo(requestID.get)
    response.setStatus(buildStatus("urn:oasis:names:tc:SAML:2.0:status:Success"))
    Logger.info("SAML response built")
    signResponse(response,loadConfig("saml.idp.cert"),loadConfig("saml.idp.private"))
  }

  private def buildStatus(status : String) : org.opensaml.saml2.core.Status = {
    val builder = new StatusBuilder().buildObject()
    val statCode = new StatusCodeBuilder().buildObject()
    statCode.setValue(status)
    builder.setStatusCode(statCode)
    builder
  }

  private def extractParam(param : String)(implicit request: Request[AnyContent]) = {
    request.body.asFormUrlEncoded.flatMap(_.get(param)).flatMap(_.headOption)
      .getOrElse(throw new SecurityException(s"Mandatory parameter, $param, missing from request"))
  }

  private def createIssuer(issuerID : String) = {
    val issuer = create[Issuer](Issuer.DEFAULT_ELEMENT_NAME)
    issuer.setValue(issuerID)
    issuer
  }

  private def createAssertion(issuer: Issuer, user : String, returnAddress : String, requestID : Option[String]) : Assertion = {
    val currentTime = new DateTime()
    val samlAssertion = create[Assertion](Assertion.DEFAULT_ELEMENT_NAME)
    samlAssertion.setID(UUID.randomUUID.toString)
    samlAssertion.setVersion(SAMLVersion.VERSION_20)
    samlAssertion.setIssuer(issuer)
    samlAssertion.setIssueInstant(currentTime)
    val subject = new SubjectBuilder().buildObject()
    val nameId = new NameIDBuilder().buildObject()
    nameId.setValue(user)
    nameId.setSPNameQualifier(returnAddress)
    nameId.setFormat(NameIdentifier.FORMAT_ATTRIB_NAME)
    subject.setNameID(nameId)

    val subjectConfirmation = new SubjectConfirmationBuilder().buildObject()
    subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer")
    val subjectConfirmationData = new SubjectConfirmationDataBuilder().buildObject()
    subjectConfirmationData.setRecipient(returnAddress)
    subjectConfirmationData.setNotOnOrAfter(currentTime.plusMinutes(5))
    if(!requestID.isEmpty)
      subjectConfirmationData.setInResponseTo(requestID.get)
    subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData)
    subject.getSubjectConfirmations().add(subjectConfirmation)
    samlAssertion.setSubject(subject)

    val audienceRestriction = new AudienceRestrictionBuilder().buildObject()
    val issuerAudience = new AudienceBuilder().buildObject()
    issuerAudience.setAudienceURI(loadConfig("saml.idp.sp"))
    audienceRestriction.getAudiences().add(issuerAudience)
    val conditions = new ConditionsBuilder().buildObject()
    conditions.setNotBefore(currentTime)
    conditions.setNotOnOrAfter(currentTime.plusMinutes(5))
    conditions.getAudienceRestrictions().add(audienceRestriction)
    samlAssertion.setConditions(conditions)

    val authStmt = new AuthnStatementBuilder().buildObject()
    authStmt.setAuthnInstant(new DateTime())

    val authContext = new AuthnContextBuilder().buildObject()
    val authCtxClassRef = new AuthnContextClassRefBuilder().buildObject()
    authCtxClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX)
    authContext.setAuthnContextClassRef(authCtxClassRef)
    authStmt.setAuthnContext(authContext)
    samlAssertion.getAuthnStatements().add(authStmt)
    samlAssertion.getAttributeStatements.add(buildAttributes(user))
    samlAssertion
  }

  private def buildAttributes(user : String) = {
    val claims = Array("username","emailAddress")
    val attStmt = new AttributeStatementBuilder().buildObject()
    for(x <- 0 to 1) {
      val attrib = new AttributeBuilder().buildObject()
      attrib.setName(claims(x))
      val stringBuilder = Configuration.getBuilderFactory().getBuilder(XSString.TYPE_NAME).asInstanceOf[XSStringBuilder]
      val stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME)
      stringValue.setValue(user)
      attrib.getAttributeValues().add(stringValue)
      attStmt.getAttributes().add(attrib)
    }
    attStmt
  }

  private def create[T](elementName: QName): T = Configuration.getBuilderFactory.getBuilder(elementName).buildObject(elementName).asInstanceOf[T]
}

object SAMLResponseController extends SAMLResponseController


