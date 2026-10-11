// Only definitive peer-input failures may be acknowledged without processing.
// Network, storage, native-process and not-yet-ready failures remain retryable.
export class RejectedMessage extends Error {}
