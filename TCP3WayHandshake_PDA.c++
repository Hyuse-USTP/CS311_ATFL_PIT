#include <iostream>
#include <stack>
#include <vector>
#include <string>
#include <iomanip> // For nice formatting

using namespace std;

// === PDA CONFIGURATION ===
enum State { q0_Listen, q1_Active, q2_Closed, qTrap_Reject };

// Helper to get state names
string getStateName(State s) {
    switch(s) {
        case q0_Listen:   return "q0 (Listen)";
        case q1_Active:   return "q1 (Active Session)";
        case q2_Closed:   return "q2 (Closed)";
        case qTrap_Reject:return "TRAP (REJECTED)";
        default:          return "Unknown";
    }
}

// Function to simulate the PDA logic
void runPDA(vector<string> packetStream, string testName) {
    // THE MEMORY STACK (The difference between DFA and PDA)
    stack<string> memoryStack;
    memoryStack.push("Z0"); // Z0: Initial Bottom Marker
    
    State currentState = q0_Listen;

    cout << "\n===========================================================" << endl;
    cout << " SCENARIO: " << testName << endl;
    cout << "===========================================================" << endl;
    cout << "START STATE: " << getStateName(currentState) << endl;
    cout << "INIT STACK:  [ Z0 ]" << endl;
    cout << "-----------------------------------------------------------" << endl;
    cout << left << setw(15) << "INPUT" << " | " << setw(25) << "ACTION / LOGIC" << " | " << "NEW STATE" << endl;
    cout << "-----------------------------------------------------------" << endl;

    for (const string& packet : packetStream) {
        string actionLog = "";
        
        // --- PDA TRANSITION LOGIC ---
        
        // 1. STATE q0 (LISTEN)
        if (currentState == q0_Listen) {
            if (packet == "SYN") {
                // Rule: Read SYN -> Push Session Token
                memoryStack.push("SESSION_ID"); 
                currentState = q1_Active;
                actionLog = "PUSH 'SESSION_ID'";
            } else {
                // Rule: Anything else -> Reject (e.g. Nmap Scan)
                currentState = qTrap_Reject;
                actionLog = "VIOLATION: No Handshake";
            }
        }
        
        // 2. STATE q1 (ACTIVE TUNNEL)
        else if (currentState == q1_Active) {
            if (packet == "FIN") {
                // Rule: Read FIN -> Pop Token -> Close
                if (!memoryStack.empty() && memoryStack.top() == "SESSION_ID") {
                    memoryStack.pop();
                    currentState = q2_Closed;
                    actionLog = "POP 'SESSION_ID'";
                }
            } 
            else {
                // Rule: Payload Agnostic (Accepts HTTP, SSH, ACK...)
                // CRITICAL CHECK: Is the Session Token on the stack?
                if (!memoryStack.empty() && memoryStack.top() == "SESSION_ID") {
                    currentState = q1_Active; // Stay in Tunnel
                    actionLog = "VERIFY Stack (OK)";
                } else {
                    // Hijack Attempt (State is q1, but Stack is missing Token)
                    currentState = qTrap_Reject;
                    actionLog = "ERROR: Stack Empty!";
                }
            }
        }
        
        // 3. STATE q2 (CLOSED)
        else if (currentState == q2_Closed) {
            // Rule: Any data after close is an intrusion
            currentState = qTrap_Reject;
            actionLog = "INTRUSION: Data after Close";
        }
        
        // 4. TRAP STATE
        else {
            currentState = qTrap_Reject;
            actionLog = "Blocked";
        }

        // Print the Step Log
        cout << left << setw(15) << packet << " | " << setw(25) << actionLog << " | " << getStateName(currentState) << endl;
        
        // Stop simulation if trapped
        if (currentState == qTrap_Reject) break;
    }

    cout << "-----------------------------------------------------------" << endl;
    
    // Final Verdict
    if (currentState == q2_Closed) {
        cout << "[SUCCESS] Traffic Pattern Validated. Session Closed Cleanly." << endl;
    } 
    else if (currentState == qTrap_Reject) {
        cout << "[ALERT]   Security Violation Detected. Packet Dropped." << endl;
    }
    else {
        cout << "[WARN]    Incomplete Session (Did not close)." << endl;
    }
    cout << endl;
}

int main() {
    // SCENARIO 1: Web Browsing (Valid)
    vector<string> webFlow = {"SYN", "ACK", "HTTP_GET", "JPG_DATA", "FIN"};
    runPDA(webFlow, "1. Standard Web Browsing (Valid)");

    // SCENARIO 2: SSH Session (Valid)
    vector<string> sshFlow = {"SYN", "ACK", "SSH_KEY", "ENCRYPTED_CMD", "FIN"};
    runPDA(sshFlow, "2. SSH Secure Session (Valid)");

    // SCENARIO 3: Nmap Scan (Attack)
    // Attacker sends FIN without SYN to map ports
    vector<string> nmapFlow = {"FIN"};
    runPDA(nmapFlow, "3. Nmap FIN Scan (Invalid Start)");

    // SCENARIO 4: Session Hijack (Attack)
    // Attacker tries to inject commands *after* the admin logs out
    vector<string> hijackFlow = {"SYN", "ACK", "SSH_KEY", "FIN", "ROOT_CMD"};
    runPDA(hijackFlow, "4. Session Hijack (Data after FIN)");

    return 0;
}