/**
 * @name Query built from user-controlled sources
 * @description Building a SQL or Java Persistence query from user-controlled sources is vulnerable to insertion of
 *              malicious code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/wave-sql-injection
 * @tags security
 *       external/cwe/cwe-089
 *       external/cwe/cwe-564
 */

import java

import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.SqlInjectionQuery


/**
 * Custom taint-tracking config that treats ValidateUsername as a sanitizer barrier.
 */
module CustomQueryInjectionFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof QueryInjectionSink }

  predicate isBarrier(DataFlow::Node node) {
      // Treat org.owasp.webgoat.lessons.sqlinjection.advanced.SanitizationHelper.SanitizeUsername() as a barrier
    exists(MethodCall mc |
    mc.getMethod().getName() = "SanitizeUsername" and
    mc.getMethod().getDeclaringType().getName() = "SanitizationHelper" and
    mc.getMethod().getDeclaringType().getPackage().getName() = "org.owasp.webgoat.lessons.sqlinjection.advanced" and
    node.asExpr() = mc
    )
    or
    QueryInjectionFlowConfig::isBarrier(node)
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    any(AdditionalQueryInjectionTaintStep s).step(node1, node2)
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module CustomQueryInjectionFlow = TaintTracking::Global<CustomQueryInjectionFlowConfig>;
import CustomQueryInjectionFlow::PathGraph

from
  QueryInjectionSink query, CustomQueryInjectionFlow::PathNode source, CustomQueryInjectionFlow::PathNode sink
where CustomQueryInjectionFlow::flowPath(source, sink) and sink.getNode() = query
select query, source, sink, "This query depends on a $@.", source.getNode(), "user-provided unsanitized value"