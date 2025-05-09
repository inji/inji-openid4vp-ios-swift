struct TestCase<T, U> {
    let input: T
    let expectedError: String?
    let expectedOutput: U?
    
    init(input: T, expectedError: String? = nil, expectedOutput: U? = nil) {
        self.input = input
        self.expectedError = expectedError
        self.expectedOutput = expectedOutput
    }
}

extension TestCase where U == Void {
    init(input: T, expectedError: String? = nil) {
        self.init(input: input, expectedError: expectedError, expectedOutput: nil)
    }
}
