#!/bin/bash

exit_with_err() {
  local msg="${1?}"
  echo "ERROR: ${msg}"
  exit 1
}

function run_orca_fs_scan() {
  cd "${GITHUB_WORKSPACE}" || exit_with_err "could not find GITHUB_WORKSPACE: ${GITHUB_WORKSPACE}"
  echo "Running Orca FS scan:"
  echo orca-cli "${GLOBAL_FLAGS[@]}" fs scan "${SCAN_FLAGS[@]}"
  orca-cli "${GLOBAL_FLAGS[@]}" fs scan "${SCAN_FLAGS[@]}"
  export ORCA_EXIT_CODE=$?

  if [[ $? -eq 1 ]]
  then
    echo "finished=false" >> "$GITHUB_OUTPUT"
  else
    echo "finished=true" >> "$GITHUB_OUTPUT"
  fi
}

function set_global_flags() {
  GLOBAL_FLAGS=()
  if [ "${INPUT_EXIT_CODE}" ]; then
    GLOBAL_FLAGS+=(--exit-code "${INPUT_EXIT_CODE}")
  fi
  if [ "${INPUT_NO_COLOR}" == "true" ]; then
    GLOBAL_FLAGS+=(--no-color)
  fi
  if [ "${INPUT_PROJECT_KEY}" ]; then
    GLOBAL_FLAGS+=(--project-key "${INPUT_PROJECT_KEY}")
  fi
  if [ "${INPUT_SILENT}" == "true" ]; then
    GLOBAL_FLAGS+=(--silent)
  fi
  if [ "${INPUT_CONFIG}" ]; then
    GLOBAL_FLAGS+=(--config "${INPUT_CONFIG}")
  fi
  if [ "${INPUT_BASELINE_CONTEXT_KEY}" ]; then
    GLOBAL_FLAGS+=(--baseline-context-key "${INPUT_BASELINE_CONTEXT_KEY}")
  fi
  if [ "${INPUT_DISABLE_BASELINE}" == "true" ]; then
    GLOBAL_FLAGS+=(--disable-baseline)
  fi
  if [ "${INPUT_DISABLE_ERR_REPORT}" == "true" ]; then
    GLOBAL_FLAGS+=(--disable-err-report)
  fi
  if [ "${INPUT_SYNC_BASELINE}" ]; then
    GLOBAL_FLAGS+=(--sync-baseline "${INPUT_SYNC_BASELINE}")
  fi
}

# Json format must be reported and be stored in a file for github annotations
function prepare_json_to_file_flags() {
  # Output directory must be provided to store the json results
  OUTPUT_FOR_JSON="${INPUT_OUTPUT}"
  CONSOLE_OUTPUT_FOR_JSON="${INPUT_CONSOLE_OUTPUT}"
  if [[ -z "${INPUT_OUTPUT}" ]]; then
    # Results should be printed to console in the selected format
    CONSOLE_OUTPUT_FOR_JSON="${INPUT_FORMAT:-table}"
    # Results should also be stored in a directory
    OUTPUT_FOR_JSON="orca_results/"
  fi

  if [[ -z "${INPUT_FORMAT}" ]]; then
    # The default format should be provided together with the one we are adding
    FORMATS_FOR_JSON="table,json"
  else
    if [[ "${INPUT_FORMAT}" == *"json"* ]]; then
      FORMATS_FOR_JSON="${INPUT_FORMAT}"
    else
      FORMATS_FOR_JSON="${INPUT_FORMAT},json"
    fi
  fi

  # Used during the annotation process
  export OUTPUT_FOR_JSON CONSOLE_OUTPUT_FOR_JSON FORMATS_FOR_JSON
}

function set_fs_scan_flags() {
  SCAN_FLAGS=()
  if [ "${INPUT_PATH}" ]; then
    SCAN_FLAGS+=("${INPUT_PATH}")
  fi
  if [ "${INPUT_DISABLE_SECRET}" = "true" ]; then
    SCAN_FLAGS+=(--disable-secret)
  fi
  if [ "${INPUT_EXCEPTIONS_FILEPATH}" ]; then
    SCAN_FLAGS+=(--exceptions-filepath "${INPUT_EXCEPTIONS_FILEPATH}")
  fi
  if [ "${INPUT_SHOW_FAILED_ISSUES_ONLY}" = "true" ]; then
    SCAN_FLAGS+=(--show-failed-issues-only)
  fi
  if [ "${INPUT_HIDE_VULNERABILITIES}" = "true" ]; then
    SCAN_FLAGS+=(--hide-vulnerabilities)
  fi
  if [ "${INPUT_NUM_CPU}" ]; then
    SCAN_FLAGS+=(--num-cpu "${INPUT_NUM_CPU}")
  fi
  if [ "${FORMATS_FOR_JSON}" ]; then
    SCAN_FLAGS+=(--format "${FORMATS_FOR_JSON}")
  fi
  if [ "${OUTPUT_FOR_JSON}" ]; then
    SCAN_FLAGS+=(--output "${OUTPUT_FOR_JSON}")
  fi
  if [ "${CONSOLE_OUTPUT_FOR_JSON}" ]; then
    SCAN_FLAGS+=(--console-output="${CONSOLE_OUTPUT_FOR_JSON}")
  fi
  if [ "${INPUT_CUSTOM_SECRET_CONTROLS}" ]; then
    SCAN_FLAGS+=(--custom-secret-controls="${INPUT_CUSTOM_SECRET_CONTROLS}")
  fi
}

function set_env_vars() {
  if [ "${INPUT_API_TOKEN}" ]; then
    export ORCA_SECURITY_API_TOKEN="${INPUT_API_TOKEN}"
  fi
}

function validate_flags() {
  [[ -n "${INPUT_PATH}" ]] || exit_with_err "Path must be provided"
  [[ "${INPUT_PATH}" != /* ]] || exit_with_err "Path shouldn't be absolute. Please provide a relative path within the repository. Use '.' to scan the entire repository"
  [[ -n "${INPUT_API_TOKEN}" ]] || exit_with_err "api_token must be provided"
  [[ -n "${INPUT_PROJECT_KEY}" ]] || exit_with_err "project_key must be provided"
  [[ -z "${INPUT_OUTPUT}" ]] || [[ "${INPUT_OUTPUT}" == */ ]] || [[ -d "${INPUT_OUTPUT}" ]] || exit_with_err "Output must be a folder (end with /)"
}

annotate() {
  if [ "${INPUT_SHOW_ANNOTATIONS}" == "false" ]; then
    exit "${ORCA_EXIT_CODE}"
  fi
  mkdir -p "/app/${OUTPUT_FOR_JSON}"
  cp "${OUTPUT_FOR_JSON}/file_system.json" "/app/${OUTPUT_FOR_JSON}/" || exit_with_err "error during copy of results"
  cd /app || exit_with_err "error during annotations initiation"
  npm run build --if-present
  node dist/index.js
}

function main() {
  validate_flags
  set_env_vars
  set_global_flags
  prepare_json_to_file_flags
  set_fs_scan_flags
  run_orca_fs_scan
  annotate
}

main "${@}"
