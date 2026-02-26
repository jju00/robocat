"""Pipeline modules for vulnerability analysis."""

from . import diff_extraction
from . import knowledge_transformation
from . import query_generation

# Re-export commonly used components
from .diff_extraction import build_function_diff_json, extract_test_version_functions
from .knowledge_transformation import extract_knowledge_pipeline, run_batch_pipeline
from .query_generation import QueryGenerator

__all__ = [
    'diff_extraction',
    'knowledge_transformation', 
    'query_generation',
    'build_function_diff_json',
    'extract_test_version_functions',
    'extract_knowledge_pipeline',
    'run_batch_pipeline',
    'QueryGenerator'
]