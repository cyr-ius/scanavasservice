from pydantic import BaseModel, Field, field_validator


class S3Tag(BaseModel):
    """S3 Tag model with validation."""

    key: str = Field(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z0-9\s+\-=._:/@]+$",
        description="S3 tag key (lowercase alphanumeric + allowed special chars)",
    )
    value: str = Field(
        ...,
        min_length=0,
        max_length=256,
        pattern=r"^[a-zA-Z0-9\s+\-=._:/@]*$",
        description="S3 tag value (alphanumeric + allowed special chars)",
    )

    @field_validator("key", mode="before")
    @classmethod
    def normalize_key(cls, v):
        """Normalize tag key to lowercase."""
        if v is None:
            return v
        return str(v).lower().strip()

    @field_validator("value", mode="before")
    @classmethod
    def normalize_value(cls, v):
        """Normalize tag value."""
        if v is None:
            return ""
        return str(v).strip()


class S3TagSet(BaseModel):
    """Collection of S3 tags with validation."""

    tags: list[S3Tag] = Field(
        default_factory=list, max_length=10, description="Maximum 10 tags per S3 object"
    )

    @field_validator("tags", mode="before")
    @classmethod
    def validate_tag_count(cls, v):
        """Ensure max 10 tags."""
        if isinstance(v, dict):
            # Convertir dict en list[S3Tag]
            return [
                S3Tag(key=k, value=str(val)) for k, val in v.items() if val is not None
            ]
        return v

    def to_tagset(self) -> dict:
        """Convert to AWS TagSet format."""
        return {"TagSet": [{"Key": tag.key, "Value": tag.value} for tag in self.tags]}

    def to_dict(self) -> dict[str, str]:
        """Convert to simple dict."""
        return {tag.key: tag.value for tag in self.tags}


class S3Tags(S3TagSet):
    """Tags for scan result."""

    @classmethod
    def from_scan_response(cls, response: "ScanResponse") -> "S3Tags":  # type: ignore # noqa: F821
        """Create tags from ScanResponse."""
        tags_dict = {
            "status": response.status,
            "timestamp": str(response.timestamp),
            "duration": str(response.duration) if response.duration else "0",
            "instance": response.instance or "unknown",
            "infos": response.infos or "none",
            "analyse": str(response.analyse) if response.analyse else "0",
        }
        return cls(tags=tags_dict)  # type: ignore

    @classmethod
    def from_aws_response(cls, aws_response: dict) -> "S3Tags":
        """Create tags from AWS get_object_tagging response."""
        tagset = aws_response.get("TagSet", [])
        tags_dict = {tag["Key"]: tag["Value"] for tag in tagset}
        return cls(tags=tags_dict)  # type: ignore

    @classmethod
    def from_dict(cls, tags: dict[str, str]) -> "S3Tags":
        """Create tags from dict."""
        return cls(tags=[S3Tag(key=k, value=v) for k, v in tags.items()])
