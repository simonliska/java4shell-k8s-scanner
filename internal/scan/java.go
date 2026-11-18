package scan

import (
	"path"
	"regexp"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// Image names that suggest Java. Only used without --exec.
var javaImageHint = regexp.MustCompile(`(?i)(jdk|jre|java|temurin|openjdk|corretto|zulu|semeru|liberica|sapmachine|graalvm|` +
	`keycloak|tomcat|jetty|wildfly|jboss|kafka|zookeeper|elasticsearch|opensearch|logstash|jenkins|sonarqube|nexus|` +
	`cassandra|solr|spark|flink|trino|neo4j|activemq|artemis)`)

// Env vars the JVM itself reads; their -XX options are always applied.
var jvmEnvVars = []string{"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"}

func looksLikeJava(c corev1.Container) bool {
	if javaImageHint.MatchString(c.Image) {
		return true
	}
	if len(c.Command) > 0 && path.Base(c.Command[0]) == "java" {
		return true
	}
	for _, e := range c.Env {
		if e.Name == "JAVA_HOME" || e.Name == "JAVA_OPTS" || slices.Contains(jvmEnvVars, e.Name) {
			return true
		}
	}
	return false
}

// jvmOptions joins everything in the spec that can carry -XX options to the JVM.
func jvmOptions(c corev1.Container) string {
	parts := slices.Concat(c.Command, c.Args)
	for _, e := range c.Env {
		if slices.Contains(jvmEnvVars, e.Name) {
			parts = append(parts, e.Value)
		}
	}
	return strings.Join(parts, " ")
}

// JDK images whose tag is the OpenJDK version, e.g. eclipse-temurin:21.0.13_9-jdk.
var versionedJDKImages = map[string]bool{"eclipse-temurin": true, "openjdk": true, "sapmachine": true}

// "21.0.13_9-jdk" -> 21.0.13. A bare "21-jdk" is a moving tag, so no match.
var jdkTag = regexp.MustCompile(`^(\d+(?:\.\d+){1,4})(?:_\d+)?(?:-|$)`)

func imageVersion(image string) string {
	image, _, _ = strings.Cut(image, "@") // drop digest
	repo, tag := image, ""
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		repo, tag = image[:i], image[i+1:]
	}
	if !versionedJDKImages[path.Base(repo)] {
		return ""
	}
	if m := jdkTag.FindStringSubmatch(tag); m != nil {
		return m[1]
	}
	return ""
}
