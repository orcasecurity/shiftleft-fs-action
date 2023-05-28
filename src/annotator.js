const core = require("@actions/core");

function getSecretDetails(secretResults) {
    let details = secretResults.catalog_control["details"];
    let recommendation = "Recommendation:\nrecomended to delete this secret or/and routet it"
    let message = `Details:\n${secretResults.catalog_control["title"]} secret was found`
    if (details) {
         message = `Details:\n${wrapWords(details)}\n`;
    }
    return `${message}\n${recommendation}`
}

function wrapWords(input, maxLineLength = 80) {
    const words = input.split(/\s+/);
    const lines = [];
    let currentLine = '';

    for (let i = 0; i < words.length; i++) {
        const word = words[i];
        if (currentLine.length + word.length > maxLineLength) {
            lines.push(currentLine.trim());
            currentLine = '';
        }
        currentLine += (currentLine ? ' ' : '') + word;
    }

    if (currentLine) {
        lines.push(currentLine.trim());
    }

    return lines.join('\n');
}

function getVulnDetails(vulnerability) {
    let description = [`Severity: ${vulnerability.severity}`]
    if (vulnerability.cvss_v2_score) {
        description.push(`CVSS2 Score: ${vulnerability.cvss_v2_score}`);
    }
    if (vulnerability.cvss_v3_score) {
        description.push(`CVSS3 Score: ${vulnerability.cvss_v3_score}`);
    }
    description.push(`Installed version: ${vulnerability["installed_version"]}`);
    let fixedVersion = vulnerability["fixed_version"]
    if (fixedVersion) {
        description.push(`Fixed version: ${fixedVersion}`);
    }
    return description.join("\n")
}

function extractSecretFinding(secretResults, annotations) {
    for (const finding of secretResults.findings) {
        annotations.push({
            file: finding["file_name"],
            startLine: finding.position["start_line"],
            endLine: finding.position["end_line"],
            priority: secretResults["priority"],
            status: secretResults["status"],
            title: `[${secretResults["priority"]}] ${secretResults.catalog_control["title"]}`,
            details: getSecretDetails(secretResults),
        });
    }
}

function extractVulnerability(results, annotations) {
    for (const vulnerability of results.vulnerabilities) {
        annotations.push({
            file: results["target"],
            // currently no start line and end line for vulnerabilities available
            startLine: 1,
            endLine: 1,
            priority: vulnerability["severity"],
            status: vulnerability.status_summary["status"],
            title: `${vulnerability["pkg_name"]} (${vulnerability["vulnerability_id"]})`,
            details: getVulnDetails(vulnerability),
        });
    }
}

function extractAnnotations(results) {
    let annotations = [];
    for (const secretResults of results.results.secret_detection.results) {
        extractSecretFinding(secretResults, annotations);
    }
    for (const vulnResults of results.vulnerabilities) {
        extractVulnerability(vulnResults, annotations);
    }
    return annotations;
}

function annotateChangesWithResults(results) {
    const annotations = extractAnnotations(results);
    annotations.forEach((annotation) => {
        let annotationProperties = {
            title: annotation.title,
            startLine: annotation.startLine,
            endLine: annotation.endLine,
            file: annotation.file,
        };
        if (annotation.status === "FAILED") {
            core.error(annotation.details, annotationProperties);
        } else {
            core.warning(annotation.details, annotationProperties);
        }
    });
}

module.exports = {
    annotateChangesWithResults,
};
