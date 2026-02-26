"""Diff extraction pipeline components."""

from .diff_extractor import (
    build_function_diff_json,
    TouchedLines,
    FunctionSpan,
    parse_touched_lines,
    extract_php_function_spans,
    find_enclosing_span,
    git_diff_file,
    git_changed_files,
    git_show_file,
    run_git,
    slice_lines,
    extract_global_snippet
)

from .tvc_extractor import (
    extract_test_version_functions,
    extract_function_block,
    git_show
)

__all__ = [
    'build_function_diff_json',
    'TouchedLines', 
    'FunctionSpan',
    'parse_touched_lines',
    'extract_php_function_spans',
    'find_enclosing_span',
    'git_diff_file',
    'git_changed_files', 
    'git_show_file',
    'run_git',
    'slice_lines',
    'extract_global_snippet',
    'extract_test_version_functions',
    'extract_function_block',
    'git_show'
]