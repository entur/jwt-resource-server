#!/usr/bin/env bash
#
# Builds a single, accurate coverage report across all reactor modules by
# feeding every module's exec/class/source data into the standalone JaCoCo
# CLI (jacococli.jar) "report" command.
#
# Why this exists: jacoco-maven-plugin's report-aggregate goal can only
# aggregate modules it has real <dependencies> on, and this project's root
# pom cannot declare such dependencies without breaking the reactor build
# (see the jacoco-maven-plugin comment in pom.xml). Feeding every module's
# raw exec/class/source data into one flat CLI report sidesteps that
# limitation entirely and correctly attributes coverage across module
# boundaries (e.g. jwt-spring-web/jwt-spring-webflux tests exercising
# jwt-spring-common).
#
# Usage: run after `mvn test` has produced target/jacoco.exec files in each
# module, e.g.:
#   mvn -B test
#   .github/scripts/jacoco-flat-report.sh
#
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

JACOCO_VERSION="0.8.15"
JACOCO_CLI_COORD="org.jacoco:org.jacoco.cli:${JACOCO_VERSION}:jar:nodeps"
OUTPUT_DIR="target/jacoco-flat-report"

# Reactor modules that contain real sources (jwt-bom is a BOM with no code
# and is intentionally excluded; the deprecated jwt-spring-grpc-ecosystem
# module is already excluded from the root <modules> list).
MODULES=(
	jwt-test/jwt-junit5-core
	jwt-test/jwt-junit5-entur
	jwt-test/jwt-junit5-spring
	jwt-client/jwt-client-core
	jwt-client/jwt-client-spring-core
	jwt-client/jwt-client-spring
	jwt-client/jwt-client-spring-resttemplate
	jwt-client/jwt-client-spring-webflux
	jwt-client/jwt-client-grpc
	jwt-server/spring/jwt-spring-web
	jwt-server/spring/jwt-spring-common
	jwt-server/spring/jwt-spring-webflux
	jwt-server/spring/jwt-spring-grpc-common
	jwt-server/spring/jwt-spring-grpc-native
)

echo "Resolving jacococli.jar (${JACOCO_CLI_COORD})..."
mvn -q dependency:get -Dartifact="${JACOCO_CLI_COORD}"
JACOCO_CLI_JAR="$(find ~/.m2/repository/org/jacoco/org.jacoco.cli -name "org.jacoco.cli-${JACOCO_VERSION}-nodeps.jar")"

args=(report)
classfiles_args=()
sourcefiles_args=()
exec_count=0

for module in "${MODULES[@]}"; do
	if [ -f "${module}/target/jacoco.exec" ]; then
		args+=("${module}/target/jacoco.exec")
		exec_count=$((exec_count + 1))
	fi
	if [ -d "${module}/target/classes" ]; then
		classfiles_args+=(--classfiles "${module}/target/classes")
	fi
	if [ -d "${module}/src/main/java" ]; then
		sourcefiles_args+=(--sourcefiles "${module}/src/main/java")
	fi
done

if [ "${exec_count}" -eq 0 ]; then
	echo "No jacoco.exec files found - did you run 'mvn test' first?" >&2
	exit 1
fi

mkdir -p "${OUTPUT_DIR}"
args+=("${classfiles_args[@]}" "${sourcefiles_args[@]}")
args+=(--html "${OUTPUT_DIR}/html" --xml "${OUTPUT_DIR}/jacoco.xml" --csv "${OUTPUT_DIR}/jacoco.csv")

echo "Building flat coverage report from ${exec_count} exec file(s)..."
java -jar "${JACOCO_CLI_JAR}" "${args[@]}"

echo "Report written to ${OUTPUT_DIR}/html/index.html"
