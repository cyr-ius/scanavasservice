class S3StorageException(Exception):
    """Storage exception."""


class S3GetObjectException(S3StorageException):
    """S3 get object errors."""


class S3MoveException(S3StorageException):
    """S3 move errors."""


class S3TaggingException(S3StorageException):
    """S3 tagging errors."""


class S3LockException(S3StorageException):
    """S3 lock errors."""


class S3UnlockException(S3StorageException):
    """S3 unlock errors."""


class S3MetadataException(S3StorageException):
    """S3 metadata errors."""


class S3BucketKeyException(S3StorageException):
    """S3 bucket/key errors."""
