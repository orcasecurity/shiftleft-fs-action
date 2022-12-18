const core = require("@actions/core");


function extractAnnotations(results) {
    let annotations = [];
    for (const controlResults of results.secret_detection.results) {
        for (const finding of controlResults.findings) {
            annotations.push({
                file: finding["file_name"],
                startLine: finding["start_line"],
                endLine: finding["end_line"],
                priority: controlResults["priority"],
                status: controlResults["status"],
                title: controlResults.catalog_control["title"],
                details: controlResults.catalog_control["title"],
            });
        }
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
