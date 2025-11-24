#include <iostream>
#include <stack>
#include <vector>
#include <string>
#include <thread>
#include <chrono>

using namespace std;

// === ANSI COLORS (The "Hacker" Look) ===
const string RESET  = "\033[0m";
const string RED    = "\033[31m";
const string GREEN  = "\033[32m";
const string YELLOW = "\033[33m";
const string BLUE   = "\033[34m";
const string CYAN   = "\033[36m";
const string BOLD   = "\033[1m";

// === VISUALIZATION HELPERS ===
void clearScreen() {
    // ANSI escape code to clear screen and move cursor to top-left
    // This reduces flickering compared to system("cls")
    cout << "\033[2J\033[1;1H";
}

void wait(int ms) {
    this_thread::sleep_for(chrono::milliseconds(ms));
}

// This function draws the entire UI frame
void drawFrame(string packetName, int activeState, stack<string> s, string statusMsg, bool isAttack) {
    clearScreen();
    
    // 1. HEADER
    cout << BOLD << CYAN << "========================================================" << RESET << endl;
    cout << "   NETWORK PROTOCOL VALIDATOR (PDA VISUALIZER)   " << endl;
    cout << BOLD << CYAN << "========================================================" << RESET << endl << endl;

    // 2. STATE MACHINE DIAGRAM
    // Dynamic highlighting based on activeState (0=q0, 1=q1, 2=q2, 3=Trap)
    string s0 = (activeState == 0) ? (GREEN + "[[ q0 ]]" + RESET) : " (q0) ";
    string s1 = (activeState == 1) ? (BLUE + "[[ q1 ]]" + RESET) : " (q1) ";
    string s2 = (activeState == 2) ? (GREEN + "[[ q2 ]]" + RESET) : " (q2) ";
    string tr = (activeState == 3) ? (RED + "[[TRAP]]" + RESET) : " TRAP ";
    
    cout << "      Start           Tunnel           Closed" << endl;
    cout << "     " << s0 << "=======>" << s1 << "=======>" << s2 << endl;
    cout << "        |               |                |   " << endl;
    cout << "        | (Bad Input)   | (Empty Stack)  | (Data after FIN)" << endl;
    cout << "        V               V                V   " << endl;
    cout << "      " << tr << "           " << tr << "           " << tr << endl << endl;

    // 3. PACKET INFO
    string pktColor = isAttack ? RED : YELLOW;
    cout << "  Current Packet:  " << pktColor << "[ " << packetName << " ]" << RESET << endl;
    cout << "  System Status:   " << statusMsg << endl << endl;

    // 4. STACK MEMORY VISUALIZATION
    cout << "  " << BOLD << "STACK MEMORY:" << RESET << endl;
    cout << "  +-------------+" << endl;

    // Convert stack to vector for printing
    vector<string> tempStack;
    stack<string> dump = s;
    while(!dump.empty()) {
        tempStack.push_back(dump.top());
        dump.pop();
    }

    if(tempStack.empty()) {
        cout << "  |             |" << endl;
        cout << "  |   " << RED << "EMPTY" << RESET << "     |" << endl;
        cout << "  |             |" << endl;
    } else {
        for(const string& val : tempStack) {
            if(val == "S")  cout << "  | " << BLUE << "[ SESSION ]" << RESET << " | <--- ACCESS TOKEN" << endl;
            if(val == "Z0") cout << "  | [ BASE Z0 ] |" << endl;
        }
    }
    cout << "  +-------------+" << endl;
    cout << "\n========================================================" << endl;
}

// === PDA LOGIC ===
enum State { q0, q1, q2, qTrap };

void runScenario(string title, vector<string> packets) {
    stack<string> mem;
    mem.push("Z0"); // Base of stack
    State curr = q0;
    
    clearScreen();
    cout << "LOADING SCENARIO: " << title << "..." << endl;
    wait(1000);

    for (const string& pkt : packets) {
        bool isAttack = false;
        string msg = "Processing...";

        // A. ANIMATE PACKET ARRIVAL
        drawFrame(pkt, curr, mem, "Incoming Traffic...", false);
        wait(1000); // Pause to let user see the packet

        // B. PROCESS LOGIC
        
        // 1. q0 -> q1 (Handshake)
        if (curr == q0) {
            if(pkt == "SYN") {
                mem.push("S");
                curr = q1;
                msg = "VALID: Handshake verified. Token Pushed.";
            } else {
                curr = qTrap; isAttack = true;
                msg = "VIOLATION: Protocol must start with SYN!";
            }
        }
        // 2. q1 -> q1 or q2 (Tunnel)
        else if (curr == q1) {
            if (pkt == "FIN") {
                // Normal Close
                if (mem.top() == "S") {
                    mem.pop();
                    curr = q2;
                    msg = "VALID: Session Teardown. Token Popped.";
                }
            } else {
                // Data / ACK / HTTP / SSH etc.
                if (mem.top() == "S") {
                    curr = q1; // Stay in tunnel
                    msg = "VALID: Traffic inside Secure Tunnel.";
                } else {
                    // HIJACK ATTEMPT (Stack Empty in q1)
                    curr = qTrap; isAttack = true;
                    msg = "CRITICAL: Stack Empty! Session Hijack Attempt!";
                }
            }
        }
        // 3. q2 -> Trap (Zombie Data)
        else if (curr == q2) {
            curr = qTrap; isAttack = true;
            msg = "INTRUSION: Data received after Connection Closed.";
        }
        // 4. Already Trapped
        else {
            curr = qTrap; isAttack = true;
            msg = "Rejected.";
        }

        // C. ANIMATE RESULT
        drawFrame(pkt, curr, mem, msg, isAttack);
        
        if(isAttack) {
            // Flash effect for attack
            wait(200); cout << "\a"; // Beep
            wait(2500); // Linger longer on error
            break;
        } else {
            wait(1200);
        }
    }
    
    cout << "\nSimulation Complete. Press ENTER to return to menu...";
    cin.ignore(); cin.get();
}

int main() {
    while(true) {
        clearScreen();
        cout << BOLD << GREEN << "=== CYBERSECURITY PROTOCOL VISUALIZER ===" << RESET << endl;
        cout << "1. Web Browsing (Valid Flow)" << endl;
        cout << "2. SSH Session (Valid Flow)" << endl;
        cout << "3. Session Hijack (Attack - Empty Stack)" << endl;
        cout << "4. Zombie Data (Attack - Data after FIN)" << endl;
        cout << "5. Exit" << endl;
        cout << "\nSelect Scenario [1-5]: ";
        
        char choice;
        cin >> choice;

        if (choice == '1') {
            vector<string> p = {"SYN", "ACK", "HTTP_GET", "JPG_DATA", "FIN"};
            runScenario("Standard Web Traffic", p);
        }
        else if (choice == '2') {
            vector<string> p = {"SYN", "ACK", "SSH_KEY", "ENCRYPTED_CMD", "FIN"};
            runScenario("Secure SSH Session", p);
        }
        else if (choice == '3') {
            // Hijack: Trying to send command without a session token
            vector<string> p = {"SYN", "ACK", "SSH_KEY", "FIN", "ROOT_CMD"}; 
            // Note: In this specific logic, FIN pops the stack. 
            // If we want to simulate Hijack *during* connection, we'd need a manual pop, 
            // but "Data after FIN" is the standard Trap demo. 
            // Let's do a 'Spoof' where we never sent SYN.
             vector<string> spoof = {"ACK", "HTTP_GET"};
             runScenario("Session Hijack / Spoofing", spoof);
        }
        else if (choice == '4') {
             vector<string> p = {"SYN", "ACK", "FIN", "MALICIOUS_DATA"};
             runScenario("Zombie Data Attack", p);
        }
        else if (choice == '5') {
            break;
        }
    }
    return 0;
}