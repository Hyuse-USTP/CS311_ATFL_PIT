# CS311_ATFL_PIT
Automata Theory and Formal Languages course work's Performance Innovative Task

This is the Protocol Validation code base for Topic 2's requirement.
It contains 3 Visualizers, and the base TCP 3-Way Handshake PDA code.

To run the visualizers: 

For ASCII Visualizer: Compile and run the "ASCIIVisualizer_TCP3WayHandshake_PDA.cpp" and the code will run on the terminal.

For HTML Visualizer: Compile and run the "HTMLVisualizer_TCP3WayHandshake_PDA.cpp", then open the generated "network_dashboard.html" and from there you can play with the visualizer yourself.

For Python Visualizer: Activate the python virtual environment, then install run "pip install -r requirements.txt" that is in the venv folder, then compile "pda_json.cpp", and then you can run the "Frontend_TCP3WayHandshake_PDA.py". From there you can play with the GUI as you please to see which scenario among the 4 visualized.


Topic 2: Network Security and Protocol Analysis

This project applies the Chomsky hierarchy to cybersecurity problems. You will implement regular expressions thatc define security patterns and malicious signatures, then convert them into minimized DFAs for efficient pattern matching in network traffic. The set of all strings matching a security rule forms a regular language, and you will demonstrate how these languages can be equivalently described by regular grammars or recognized by finite state machines.

For protocol validation, you will design Pushdown Automata that verify proper sequencing in network protocols like TCP handshakes, where the stack is essential for tracking nested conversation states.

Develop a simulator using C++ that will highlight the practical limitations of regular languages by showing how simple pattern matching (handled by DFAs) differs from protocol validation (requiring PDAs), illustrating the theoretical boundaries between language classes in a security context.

Sample Case Scenario: Detecting Network Intrusion Attempts