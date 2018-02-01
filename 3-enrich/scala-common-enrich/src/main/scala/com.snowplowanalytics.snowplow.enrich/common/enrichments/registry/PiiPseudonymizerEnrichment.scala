/*
 * Copyright (c) 2017-2018 Snowplow Analytics Ltd. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */

package com.snowplowanalytics
package snowplow.enrich
package common.enrichments.registry

// Scala
import scala.collection.JavaConverters._

// Scala libraries
import org.json4s
import org.json4s.JValue
import org.json4s.JsonAST._
import org.json4s.jackson.JsonMethods
import org.json4s.jackson.JsonMethods.{compact, parse, render}
import org.json4s.DefaultFormats

// Java
import java.security.{MessageDigest, NoSuchAlgorithmException}

// Java libraries
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.{ObjectNode, TextNode}
import com.fasterxml.jackson.databind.node.ArrayNode
import com.jayway.jsonpath.spi.json.JacksonJsonNodeJsonProvider
import com.jayway.jsonpath.{Configuration, JsonPath => JJsonPath, Option => JOption}
import com.jayway.jsonpath.MapFunction

// Scalaz
import scalaz._
import Scalaz._

// Iglu
import iglu.client.validation.ProcessingMessageMethods._
import iglu.client.{SchemaCriterion, SchemaKey}

// This project
import common.ValidatedNelMessage
import common.utils.ScalazJson4sUtils
import common.outputs.EnrichedEvent

object PiiConstants {
//  type ModifiedFields = List[ModifedField]
//  type Mutator = (EnrichedEvent, (String, PiiStrategy) => String) => ModifiedFields
  type Mutator = (EnrichedEvent, PiiStrategy, (String, PiiStrategy) => String) => Unit

  /**
   * This and the next constant maps from a config field name to an EnrichedEvent mutator. The structure is such so that
   * it preserves type safety, and it can be easily replaced in the future by generated code that will use the config as
   * input.
   */
  val ScalarMutators: Map[String, Mutator] = Map(
    "user_id" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.user_id = fn(event.user_id, strategy)
    },
    "user_ipaddress" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.user_ipaddress = fn(event.user_ipaddress, strategy)
    },
    "user_fingerprint" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.user_fingerprint = fn(event.user_fingerprint, strategy)
    },
    "domain_userid" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.domain_userid = fn(event.domain_userid, strategy)
    },
    "network_userid" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.network_userid = fn(event.network_userid, strategy)
    },
    "ip_organization" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.ip_organization = fn(event.ip_organization, strategy)
    },
    "ip_domain" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.ip_domain = fn(event.ip_domain, strategy)
    },
    "tr_orderid" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.tr_orderid = fn(event.tr_orderid, strategy)
    },
    "ti_orderid" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.ti_orderid = fn(event.ti_orderid, strategy)
    },
    "mkt_term" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.mkt_term = fn(event.mkt_term, strategy)
    },
    "mkt_content" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.mkt_content = fn(event.mkt_content, strategy)
    },
    "se_category" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.se_category = fn(event.se_category, strategy)
    },
    "se_action" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.se_action = fn(event.se_action, strategy)
    },
    "se_label" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.se_label = fn(event.se_label, strategy)
    },
    "se_property" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.se_property = fn(event.se_property, strategy)
    },
    "mkt_clickid" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.mkt_clickid = fn(event.mkt_clickid, strategy)
    },
    "refr_domain_userid" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.refr_domain_userid = fn(event.refr_domain_userid, strategy)
    },
    "domain_sessionid" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.domain_sessionid = fn(event.domain_sessionid, strategy)
    }
  )

  val JsonMutators: Map[String, Mutator] = Map(
    "contexts" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.contexts = fn(event.contexts, strategy)
    },
    "derived_contexts" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.derived_contexts = fn(event.derived_contexts, strategy)
    },
    "unstruct_event" -> { (event: EnrichedEvent, strategy: PiiStrategy, fn: (String, PiiStrategy) => String) =>
      event.unstruct_event = fn(event.unstruct_event, strategy)
    }
  )
}

/**
 * PiiField trait. This corresponds to a configuration top-level field (i.e. either a scalar or a JSON field) along with
 * a function to apply that strategy to the EnrichedEvent POJO (A scalar field is represented in config py "pojo")
 */
sealed trait PiiField {
  import PiiConstants.Mutator

  /**
   * The POJO mutator for this field
   *
   * @return fieldMutator
   */
  def fieldMutator: Mutator

  /**
   * Gets an enriched event from the enrichment manager and modifies it according to the specified strategy.
   *
   * @param event The enriched event
   */
  def transform(event: EnrichedEvent, strategy: PiiStrategy): Unit = fieldMutator(event, strategy, applyStrategy)

  protected def applyStrategy(fieldValue: String, strategy: PiiStrategy): String
}

/**
 * PiiStrategy trait. This corresponds to a strategy to apply to a single field. Currently only String input is
 * supported.
 */
sealed trait PiiStrategy {
  def scramble(clearText: String): String
}

/**
 * Companion object. Lets us create a PiiPseudonymizerEnrichment
 * from a JValue.
 */
object PiiPseudonymizerEnrichment extends ParseableEnrichment {
  import PiiConstants._

  implicit val json4sFormats = DefaultFormats

  override val supportedSchema =
    SchemaCriterion("com.snowplowanalytics.snowplow.enrichments", "pii_enrichment_config", "jsonschema", 2, 0, 0)

  def parse(config: JValue, schemaKey: SchemaKey): ValidatedNelMessage[PiiPseudonymizerEnrichment] = {
    for {
      conf <- matchesSchema(config, schemaKey)
      enabled                 = ScalazJson4sUtils.extract[Boolean](conf, "enabled").toOption.getOrElse(false)
      emitIdentificationEvent = ScalazJson4sUtils.extract[Boolean](conf, "emitIdentificationEvent").toOption.getOrElse(false)
      piiFields        <- ScalazJson4sUtils.extract[List[JObject]](conf, "parameters", "pii").leftMap(_.getMessage)
      strategyFunction <- extractStrategyFunction(config)
      hashFunction     <- getHashFunction(strategyFunction)
      piiFieldList     <- extractFields(piiFields)
    } yield
      if (enabled) PiiPseudonymizerEnrichment(piiFieldList, emitIdentificationEvent, PiiStrategyPseudonymize(hashFunction))
      else PiiPseudonymizerEnrichment(List(),               false,                   PiiStrategyPseudonymize(hashFunction))
  }.leftMap(_.toProcessingMessageNel)

  private def getHashFunction(strategyFunction: String): Validation[String, MessageDigest] =
    try {
      MessageDigest.getInstance(strategyFunction).success
    } catch {
      case e: NoSuchAlgorithmException =>
        s"Could not parse PII enrichment config: ${e.getMessage}".failure
    }

  private def extractFields(piiFields: List[JObject]): Validation[String, List[PiiField]] =
    piiFields.map {
      case field: JObject =>
        if (ScalazJson4sUtils.fieldExists(field, "pojo"))
          extractString(field, "pojo", "field").flatMap(extractPiiScalarField(_))
        else if (ScalazJson4sUtils.fieldExists(field, "json")) extractPiiJsonField(field \ "json")
        else s"PII Configuration: pii field does not include 'pojo' nor 'json' fields. Got: [${compact(field)}]".failure
      case json => s"PII Configuration: pii field does not contain an object. Got: [${compact(json)}]".failure
    }.sequenceU

  private def extractPiiScalarField(fieldName: String): Validation[String, PiiScalar] =
    ScalarMutators
      .get(fieldName)
      .map(PiiScalar(_).success)
      .getOrElse(s"The specified pojo field ${fieldName} is not supported".failure)

  private def extractPiiJsonField(jsonField: JValue): Validation[String, PiiJson] =
    (extractString(jsonField, "field")
      .flatMap(
        fieldName =>
          JsonMutators
            .get(fieldName)
            .map(_.success)
            .getOrElse(s"The specified json field ${compact(jsonField)} is not supported".failure)) |@|
      extractString(jsonField, "schemaCriterion").flatMap(sc => SchemaCriterion.parse(sc).leftMap(_.getMessage)) |@|
      extractString(jsonField, "jsonPath")) { (fieldMutator: Mutator, sc: SchemaCriterion, jsonPath: String) =>
      PiiJson(fieldMutator, sc, jsonPath)
    }

  private def extractString(jValue: JValue, field: String, tail: String*): Validation[String, String] =
    ScalazJson4sUtils.extract[String](jValue, field, tail: _*).leftMap(_.getMessage)

  private def extractStrategyFunction(config: JValue): Validation[String, String] =
    ScalazJson4sUtils
      .extract[String](config, "parameters", "strategy", "pseudonymize", "hashFunction")
      .leftMap(_.getMessage)

  private def matchesSchema(config: JValue, schemaKey: SchemaKey): Validation[String, JValue] =
    if (supportedSchema.matches(schemaKey)) {
      config.success
    } else {
      "Schema key %s is not supported. A '%s' enrichment must have schema '%s'."
        .format(schemaKey, supportedSchema.name, supportedSchema)
        .failure
    }
}

/**
 * The PiiPseudonymizerEnrichment runs after all other enrichments to find fields that are configured as PII (personally
 * identifiable information) and apply some anonymization (currently only pseudonymization) on them. Currently a single
 * strategy for all the fields is supported due to the config format, and there is only one implemented strategy,
 * however the enrichment supports a strategy per field.
 *
 * The user may specify two types of fields POJO or JSON. A POJO field is effectively a scalar field in the
 * EnrichedEvent, whereas a JSON is a "context" formatted field and it can be wither a scalar in the case of
 * unstruct_event or an array in the case of derived_events and contexts
 *
 * @param fieldList a list of configured PiiFields
 * @param emitIdentificationEvent whether to emit an identification event
 * @param strategy the pseudonymization strategy to use
 */
case class PiiPseudonymizerEnrichment(fieldList: List[PiiField], emitIdentificationEvent: Boolean, strategy: PiiStrategy)
    extends Enrichment {
  def transformer(event: EnrichedEvent): Unit = fieldList.foreach(_.transform(event, strategy))
}

/**
 * Specifies a scalar field in POJO and the strategy that should be applied to it.
 * @param fieldMutator the field mutator where the strategy will be applied
 */
final case class PiiScalar(fieldMutator: PiiConstants.Mutator) extends PiiField {
  override def applyStrategy(fieldValue: String, strategy: PiiStrategy): String =
    if (fieldValue != null) strategy.scramble(fieldValue) else null
}

/**
 * Specifies a strategy to use, a field mutator where the JSON can be found in the EnrichedEvent POJO, a schema criterion to
 * discriminate which contexts to apply this strategy to, and a json path within the contexts where this strategy will
 * be applied (the path may correspond to multiple fields).
 *
 * @param fieldMutator the field mutator for the json field
 * @param schemaCriterion the schema for which the strategy will be applied
 * @param jsonPath the path where the strategy will be applied
 */
final case class PiiJson(fieldMutator: PiiConstants.Mutator, schemaCriterion: SchemaCriterion, jsonPath: String) extends PiiField {
  implicit val json4sFormats = DefaultFormats

  override def applyStrategy(fieldValue: String, strategy: PiiStrategy): String =
    if (fieldValue != null) {
      compact(render(parse(fieldValue) match {
        case JObject(jObject) => {
          val jObjectMap = jObject.toMap
          val updated = jObjectMap.filterKeys(_ == "data").mapValues {
            case JArray(contexts) =>
              JArray(contexts.map {
                case JObject(context) => modifyObjectIfSchemaMatches(context, strategy)
                case x                => x
              })
            case JObject(unstructEvent) => modifyObjectIfSchemaMatches(unstructEvent, strategy)
            case x                      => x
          }
          JObject((jObjectMap ++ updated).toList)
        }
        case x => x
      }))
    } else null

  private def modifyObjectIfSchemaMatches(context: List[(String, json4s.JValue)], strategy: PiiStrategy): JObject = {
    val fieldsObj = context.toMap
    (for {
      schema              <- fieldsObj.get("schema")
      parsedSchemaMatches <- SchemaKey.parse(schema.extract[String]).map(schemaCriterion.matches).toOption
      data                <- fieldsObj.get("data")
      if parsedSchemaMatches
    } yield
      JObject(fieldsObj.updated("schema", schema).updated("data", jsonPathReplace(data, strategy)).toList)).getOrElse(JObject(context))
  }

  // Configuration for JsonPath
  private val JsonPathConf =
    Configuration.builder().options(JOption.SUPPRESS_EXCEPTIONS).jsonProvider(new JacksonJsonNodeJsonProvider()).build()

  /**
   * Replaces a value in the given context data with the result of applying the strategy that value.
   */
  private def jsonPathReplace(jValue: JValue, strategy: PiiStrategy): JValue = {
    val objectNode      = JsonMethods.mapper.valueToTree[ObjectNode](jValue)
    val documentContext = JJsonPath.using(JsonPathConf).parse(objectNode)
    documentContext.map(
      jsonPath,
      new MapFunction {
        override def map(currentValue: AnyRef, configuration: Configuration): AnyRef = currentValue match {
          case s: String => strategy.scramble(s)
          case a: ArrayNode =>
            a.elements.asScala.map {
              case t: TextNode     => strategy.scramble(t.asText())
              case default: AnyRef => default
            }
          case default: AnyRef => default
        }
      }
    )
    JsonMethods.fromJsonNode(documentContext.json[JsonNode]())
  }
}

/**
 * Implements a pseudonymization strategy using any algorithm known to MessageDigest
 * @param hashFunction the MessageDigest function to apply
 */
case class PiiStrategyPseudonymize(hashFunction: MessageDigest) extends PiiStrategy {
  val TextEncoding                                 = "UTF-8"
  override def scramble(clearText: String): String = hash(clearText)
  def hash(text: String): String                   = String.format("%064x", new java.math.BigInteger(1, hashFunction.digest(text.getBytes(TextEncoding))))
}

/**
 * The modified field trait represents an item that is transformed in either the JSON or a scalar mutators.
 */
sealed trait ModifedField

case class ScalarModifiedField(fieldName: String, originalValue: String, modifiedValue: String) extends ModifedField
case class JsonModifiedField(field: String,       originalValue: String, modifiedValue: String, jsonPath: String) extends ModifedField
