const core = require("@actions/core");

function getDetail(controlResults, file) {
    let title = controlResults.catalog_control["title"];
    let details = `Recommendation: Secret was detected on rule: ${title}`
    return details
}

function extract_secret_finding(controlResults, annotations) {
    for (const finding of controlResults.findings) {
        annotations.push({
            file: finding["file_name"],
            startLine: finding["start_line"],
            endLine: finding["end_line"],
            priority: controlResults["priority"],
            status: controlResults["status"],
            title: controlResults.catalog_control["title"],
            details: getDetail(controlResults, finding),
        });
    }
}

function extract_vulnerability_finding(controlResults, annotations) {
    for (const finding of controlResults.vulnerabilities) {
        annotations.push({
            file: controlResults["target"],
            // currently no start line and end line for vulnerabilities aviliable
            startLine: 1,
            endLine: 1,
            // priority: controlResults["priority"],
            status: controlResults.status_summary["status"],
            title: finding["vulnerability_id"],
            details: getDetail(controlResults, finding),
        });
    }
}

function extractAnnotations(results) {
    let annotations = [];
    console.log("\nextract result is :\n")
    console.log(results.vulnerabilities)
    for (const controlResults of results.results.secret_detection.results) {
            console.log("control result is:")
            console.log(controlResults)
        extract_secret_finding(controlResults, annotations);
    }
    for (const controlResults of results.vulnerabilities) {
            console.log("control result is:")
            console.log(controlResults)
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
