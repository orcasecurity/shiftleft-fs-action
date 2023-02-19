const core = require("@actions/core");

function getSecretDetails(secretResults) {
    let title = secretResults.catalog_control["title"];
    return `${title} secret was found`
}

function getVulnDetails(vulnerability) {
    let scoreMessage = '';
    if (vulnerability.cvss_v2_score) {
        scoreMessage += `CVSS2 Score: ${vulnerability.cvss_v2_score}\n`;
    }
    if (vulnerability.cvss_v3_score) {
        scoreMessage += `CVSS3 Score: ${vulnerability.cvss_v3_score}\n`;
    }
    let fixed = vulnerability["fixed_version"]
    let installed = vulnerability["installed_version"]
    return `Severity: ${vulnerability.severity}\n${scoreMessage}Installed version: ${installed}\nFixed version:${fixed}`
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
            // vulnerability does not return real path on github, so we need to concatenate path given by github
            file: `${process.env.INPUT_PATH}/${results["target"]}`,
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
