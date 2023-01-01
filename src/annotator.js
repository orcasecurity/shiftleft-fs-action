const core = require("@actions/core");

function get_secret_detail(controlResults, file) {
    let title = controlResults.catalog_control["title"];
    let details = `Recommendation: Secret was detected on rule: ${title}`
    return details
}

function get_vuln_detail(controlResults, finding) {
    let title = finding["vulnerability_id"]
    let fixed_version = finding["fixed_version"]
    let pkg_name = finding["pkg_name"]
    let details = `Recommendation: Upgrade pkg to version: ${fixed_version}, to fix ${title} in ${pkg_name}`
    return details
}

function extract_secret_finding(controlResults, annotations) {
    for (const finding of controlResults.findings) {
        annotations.push({
            file: finding["file_name"],
            startLine: finding.position["start_line"],
            endLine: finding.position["end_line"],
            priority: controlResults["priority"],
            status: controlResults["status"],
            title: controlResults.catalog_control["title"],
            details: get_secret_detail(controlResults, finding),
        });
    }
}

function extract_vulnerability_finding(controlResults, annotations) {
    for (const finding of controlResults.vulnerabilities) {
        annotations.push({
            // vulnerability does not return real path on github, so we need to concatenate path given by github
            file: process.env.INPUT_PATH+"/"+controlResults["target"],
            // currently no start line and end line for vulnerabilities available
            startLine: 1,
            endLine: 1,
            priority: finding["severity"],
            status: finding.status_summary["status"],
            title: finding["vulnerability_id"],
            details: get_vuln_detail(controlResults, finding),
        });
    }
}

function extractAnnotations(results) {
    let annotations = [];
    for (const controlResults of results.results.secret_detection.results) {
        extract_secret_finding(controlResults, annotations);
    }
    for (const controlResults of results.vulnerabilities) {
        extract_vulnerability_finding(controlResults, annotations);
    }
    return annotations;
}

function annotateChangesWithResults(results) {
    const annotations = extractAnnotations(results);
    annotations.forEach((annotation) => {
        let annotationProperties = {
            title: `[${annotation.priority}] ${annotation.title}`,
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
