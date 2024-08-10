#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ScriptError {
    ReadError {
        expected_bytes: usize,
        available_bytes: usize,
    },
    InvalidOpcode,
    PushSize,
    OpCount,
    DisabledOpcode,
    ScriptSize,
    MinimalData,
    StackSize,
    UnbalancedConditional,
    UpgradableNops,
    InvalidStackOperation,
    OpReturn,
}
