#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ScriptError {
    OpReturn,

    ScriptSize,
    PushSize,
    OpCount,
    StackSize,

    BadOpcode,
    DisabledOpcode,
    InvalidStackOperation,
    UnbalancedConditional,

    MinimalData,

    DiscourageUpgradableNOPs,

    ReadError {
        expected_bytes: usize,
        available_bytes: usize,
    },
}
