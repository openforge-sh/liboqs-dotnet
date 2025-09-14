#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Starting code coverage collection for all test projects...${NC}"

echo -e "${YELLOW}Cleaning previous coverage results...${NC}"
find . -type d -name "TestResults" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name "CoverageReport" -exec rm -rf {} + 2>/dev/null || true
find . -name "*.cobertura.xml" -delete 2>/dev/null || true

mkdir -p TestResults

echo -e "${GREEN}Running tests with coverage collection...${NC}"
dotnet test -- --coverage --coverage-output-format cobertura --coverage-output coverage.cobertura.xml

echo -e "${YELLOW}Finding coverage files...${NC}"
COVERAGE_FILES=$(find . -path "*/bin/*/TestResults/coverage.cobertura.xml" -type f)

if [ -z "$COVERAGE_FILES" ]; then
    echo -e "${RED}No coverage files found!${NC}"
    exit 1
fi

echo -e "${GREEN}Found coverage files:${NC}"
echo "$COVERAGE_FILES"

if ! command -v reportgenerator &> /dev/null; then
    echo -e "${YELLOW}Installing ReportGenerator tool...${NC}"
    dotnet tool install -g dotnet-reportgenerator-globaltool
fi

echo -e "${GREEN}Generating merged coverage report...${NC}"
reportgenerator \
    -reports:"tests/**/bin/**/TestResults/coverage.cobertura.xml" \
    -targetdir:"./CoverageReport" \
    -reporttypes:"HtmlInline_AzurePipelines;Cobertura;TextSummary" \
    -assemblyfilters:"+OpenForge.Cryptography.LibOqs*;-*.Tests" \
    -classfilters:"-*Native*;-*.Tests.*" \
    -filefilters:"-**/tests/**;-**/obj/**" \
    -verbosity:"Info"

if [ -f "./CoverageReport/Summary.txt" ]; then
    echo -e "${GREEN}Coverage Summary:${NC}"
    cat "./CoverageReport/Summary.txt"
fi

echo -e "${GREEN}Coverage report generated at: ./CoverageReport/index.html${NC}"
echo -e "${GREEN}Merged Cobertura file at: ./CoverageReport/Cobertura.xml${NC}"