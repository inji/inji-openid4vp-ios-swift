struct TestCase<T> {
    let input: T
    let expectedError: String?
    let expectedOutput: T?
    
    init(input: T, expectedError: String? = nil, expectedOutput: T? = nil) {
        self.input = input
        self.expectedError = expectedError
        self.expectedOutput = expectedOutput
    }
}
