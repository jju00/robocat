from pydantic import BaseModel, Field


class DiffQueryDTO(BaseModel):
    id: int = Field(..., description="Unique query identifier")

    project: str
    from_version: str
    test_version: str

    file_path: str
    function: str = Field(..., description="Fully qualified function name")

    full_code: str = Field(..., description="Full source code of the function")

    purpose: str = Field(..., description="One-sentence summary of the function purpose")

    function_summary: str = Field(
        ...,
        description="Step-by-step summary of the function behavior"
    )