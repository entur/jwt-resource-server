#!/bin/bash
set -e

version=$(xmllint --xpath '/*[local-name()="project"]/*[local-name()="version"]/text()' pom.xml)
echo "Set version $version"
mvn -U versions:set -DnewVersion="${version}"
