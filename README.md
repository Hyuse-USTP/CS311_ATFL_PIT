# CS311_ATFL_PIT
Automata Theory and Formal Languages course work's Performance Innovative Task

This is the Protocol Validation code base for Topic 2's requirement.

Topic 2: Network Security and Protocol Analysis

This project applies the Chomsky hierarchy to cybersecurity problems. You will implement regular expressions thatc define security patterns and malicious signatures, then convert them into minimized DFAs for efficient pattern matching in network traffic. The set of all strings matching a security rule forms a regular language, and you will demonstrate how these languages can be equivalently described by regular grammars or recognized by finite state machines.

For protocol validation, you will design Pushdown Automata that verify proper sequencing in network protocols like TCP handshakes, where the stack is essential for tracking nested conversation states.

Develop a simulator using C++ that will highlight the practical limitations of regular languages by showing how simple pattern matching (handled by DFAs) differs from protocol validation (requiring PDAs), illustrating the theoretical boundaries between language classes in a security context.

Sample Case Scenario: Detecting Network Intrusion Attempts