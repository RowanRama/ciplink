use std::fmt;

/// Result alias for ciplink operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// What kind of failure a [`TagError`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// No such tag, member, element or bit.
    NotFound,
    /// The write value does not fit the type (rejected locally or by the controller).
    BadValue,
    /// Malformed request: syntax, element count, bit on a REAL, path size.
    BadRequest,
    /// Exists but is not accessible: privilege, AOI local tag, keyswitch or password.
    Access,
    /// Nothing was done and it may work later: reload backoff, state conflict, busy.
    Refused,
    /// The tag table changed during the request, the result was discarded.
    TableChanged,
    /// The request or reply was lost or could not be parsed.
    Comm,
    /// Any other controller status.
    Device,
    /// An error that was not classified.
    Other,
}

impl ErrorKind {
    /// The lowercase name used by the Python package (`ErrorKind.value`).
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::NotFound => "not_found",
            ErrorKind::BadValue => "bad_value",
            ErrorKind::BadRequest => "bad_request",
            ErrorKind::Access => "access",
            ErrorKind::Refused => "refused",
            ErrorKind::TableChanged => "table_changed",
            ErrorKind::Comm => "comm",
            ErrorKind::Device => "device",
            ErrorKind::Other => "other",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A per-tag error: its message, kind, and the CIP general status and first extended status word of a
/// controller error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagError {
    /// Human readable message.
    pub message: String,
    /// Classification of the failure.
    pub kind: ErrorKind,
    /// CIP general status of a controller error.
    pub status: Option<u8>,
    /// First extended status word of a controller error.
    pub ext: Option<u16>,
}

impl TagError {
    /// A TagError without a controller status.
    pub fn new(message: impl Into<String>, kind: ErrorKind) -> Self {
        TagError {
            message: message.into(),
            kind,
            status: None,
            ext: None,
        }
    }
}

impl fmt::Display for TagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// Errors raised by ciplink, one variant per exception class of the Python package.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum Error {
    /// Connection related failure (`CommError`).
    #[error("{0}")]
    Comm(String),
    /// Binary encoding or decoding failed (`DataError`).
    #[error("{0}")]
    Data(String),
    /// Decoding found no data at all where a value should start (`BufferEmptyError`).
    #[error("")]
    BufferEmpty,
    /// A reply could not be used (`ResponseError`); `kind` is set when the cause is classified.
    #[error("{message}")]
    Response {
        /// Message.
        message: String,
        /// Classification carried with the error, if any.
        kind: Option<ErrorKind>,
        /// CIP general status, if a controller status caused it.
        status: Option<u8>,
        /// First extended status word, if any.
        ext: Option<u16>,
    },
    /// A request could not be built from the caller's input (`RequestError`).
    #[error("{message}")]
    Request {
        /// Message.
        message: String,
        /// Classification carried with the error, if any.
        kind: Option<ErrorKind>,
    },
}

impl Error {
    /// A `RequestError` without a classification.
    pub fn request(message: impl Into<String>) -> Self {
        Error::Request {
            message: message.into(),
            kind: None,
        }
    }

    /// A `RequestError` carrying an [`ErrorKind`].
    pub fn request_kind(message: impl Into<String>, kind: ErrorKind) -> Self {
        Error::Request {
            message: message.into(),
            kind: Some(kind),
        }
    }

    /// A `ResponseError` without a classification.
    pub fn response(message: impl Into<String>) -> Self {
        Error::Response {
            message: message.into(),
            kind: None,
            status: None,
            ext: None,
        }
    }

    /// A `ResponseError` carrying a [`TagError`]'s classification.
    pub fn response_tag(error: TagError) -> Self {
        Error::Response {
            message: error.message,
            kind: Some(error.kind),
            status: error.status,
            ext: error.ext,
        }
    }

    /// A `DataError`.
    pub fn data(message: impl Into<String>) -> Self {
        Error::Data(message.into())
    }

    /// A `CommError`.
    pub fn comm(message: impl Into<String>) -> Self {
        Error::Comm(message.into())
    }

    /// The classification this error carries, if any.
    pub fn carried_kind(&self) -> Option<ErrorKind> {
        match self {
            Error::Response { kind, .. } | Error::Request { kind, .. } => *kind,
            _ => None,
        }
    }

    /// The default kind of an error caught around a request: RequestError is a bad request, CommError a
    /// communication failure, anything else a device error.
    pub fn default_kind(&self) -> ErrorKind {
        match self {
            Error::Request { .. } => ErrorKind::BadRequest,
            Error::Comm(_) => ErrorKind::Comm,
            _ => ErrorKind::Device,
        }
    }

    /// This error as a [`TagError`]: the kind (and status) it carries, else `kind`; its message unless
    /// `message` replaces it.
    pub fn to_tag_error(&self, kind: ErrorKind, message: Option<String>) -> TagError {
        let message = message.unwrap_or_else(|| self.to_string());
        match self {
            Error::Response {
                kind: Some(carried),
                status,
                ext,
                ..
            } => TagError {
                message,
                kind: *carried,
                status: *status,
                ext: *ext,
            },
            Error::Request {
                kind: Some(carried),
                ..
            } => TagError::new(message, *carried),
            _ => TagError::new(message, kind),
        }
    }
}
