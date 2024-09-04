from tenacity import Future, RetryError


class MaxUMAFlowsReachedError(RetryError):
    def __init__(self, last_attempt: Future) -> None:
        # Increment manually because we made an uncounted attempt outside of the retry
        last_attempt.attempt_number += 1
        super().__init__(last_attempt)
