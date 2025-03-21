struct TestCase<T> {
    let input: T
    let expectedError: String?
    
    init(input: T, expectedError: String? = nil) {
        self.input = input
        self.expectedError = expectedError
    }
}
