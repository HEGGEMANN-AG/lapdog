#[derive(Clone, Copy, Debug)]
pub enum ResultCode {
    Success,
    OperationsError,
    ProtocolError,
    TimeLimitExceeded,
    SizeLimitExceeded,
    CompareFalse,
    CompareTrue,
    AuthMethodNotSupported,
    StrongerAuthRequired,
    Referral,
    AdminLimitExceeded,
    UnavailableCriticalExtension,
    ConfidentialityRequired,
    SaslBindInProgress,
    NoSuchAttribute,
    UndefinedAttributeType,
    InappropriateMatching,
    ConstraintViolation,
    AttributeOrValueExists,
    InvalidAttributeSyntax,
    NoSuchObject,
    AliasProblem,
    InvalidDNSyntax,
    AliasDereferencingProblem,
    InappropriateAuthentication,
    InvalidCredentials,
    InsufficientAccessRights,
    Busy,
    Unavailable,
    UnwillingToPerform,
    LoopDetect,
    NamingViolation,
    ObjectClassViolation,
    NotAllowedOnNonLeaf,
    NotAllowedOnRDN,
    EntryAlreadyExists,
    ObjectClassModsProhibited,
    AffectsMultipleDSAs,
    Other,
}

impl ResultCode {
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Success),
            1 => Some(Self::OperationsError),
            2 => Some(Self::ProtocolError),
            3 => Some(Self::TimeLimitExceeded),
            4 => Some(Self::SizeLimitExceeded),
            5 => Some(Self::CompareFalse),
            6 => Some(Self::CompareTrue),
            7 => Some(Self::AuthMethodNotSupported),
            8 => Some(Self::StrongerAuthRequired),

            10 => Some(Self::Referral),
            11 => Some(Self::AdminLimitExceeded),
            12 => Some(Self::UnavailableCriticalExtension),
            13 => Some(Self::ConfidentialityRequired),
            14 => Some(Self::SaslBindInProgress),

            16 => Some(Self::NoSuchAttribute),
            17 => Some(Self::UndefinedAttributeType),
            18 => Some(Self::InappropriateMatching),
            19 => Some(Self::ConstraintViolation),
            20 => Some(Self::AttributeOrValueExists),
            21 => Some(Self::InvalidAttributeSyntax),

            32 => Some(Self::NoSuchObject),
            33 => Some(Self::AliasProblem),
            34 => Some(Self::InvalidDNSyntax),

            36 => Some(Self::AliasDereferencingProblem),

            48 => Some(Self::InappropriateAuthentication),
            49 => Some(Self::InvalidCredentials),
            50 => Some(Self::InsufficientAccessRights),
            51 => Some(Self::Busy),
            52 => Some(Self::Unavailable),
            53 => Some(Self::UnwillingToPerform),
            54 => Some(Self::LoopDetect),

            64 => Some(Self::NamingViolation),
            65 => Some(Self::ObjectClassViolation),
            66 => Some(Self::NotAllowedOnNonLeaf),
            67 => Some(Self::NotAllowedOnRDN),
            68 => Some(Self::EntryAlreadyExists),
            69 => Some(Self::ObjectClassModsProhibited),

            71 => Some(Self::AffectsMultipleDSAs),

            80 => Some(Self::Other),

            _ => None,
        }
    }
}
