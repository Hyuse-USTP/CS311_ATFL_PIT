#include <iostream>
#include <vector>
#include <string>
#include <stack>
#include <thread>
#include <chrono>

using namespace std;

// Helper to format JSON with the new "Analysis" field
void sendJSON(string type, string pkt, int state, string stackTop, string desc, string analysis, bool attack) {
    // Simple manual JSON formatting
    cout << "{"
         << "\"type\": \"" << type << "\", "
         << "\"packet\": \"" << pkt << "\", "
         << "\"state\": " << state << ", "
         << "\"stackTop\": \"" << stackTop << "\", "
         << "\"desc\": \"" << desc << "\", "
         << "\"analysis\": \"" << analysis << "\", "
         << "\"isAttack\": " << (attack ? "true" : "false")
         << "}" << endl;
}

void runScenario(int id) {
    vector<string> packets;
    string name;
    
    // DEFINING THE 4 SCENARIOS
    if(id == 1) { 
        packets = {"SYN", "ACK", "HTTP_GET", "JPG_DATA", "FIN"}; 
        name = "Web Browsing (Safe)"; 
    }
    else if(id == 2) { 
        packets = {"SYN", "ACK", "SSH_KEY", "ENCRYPT_CMD", "FIN"}; 
        name = "SSH Session (Safe)"; 
    }
    else if(id == 3) { 
        packets = {"SYN", "ACK", "SSH_KEY", "FIN", "ROOT_CMD"}; 
        name = "Session Hijack (Attack)"; 
    }
    else if(id == 4) { 
        packets = {"FIN"}; 
        name = "Nmap Scan (Attack)"; 
    }
    
    stack<string> mem;
    mem.push("Z0");
    int state = 0; // 0=q0, 1=q1, 2=q2, 3=Trap
    bool hasSession = false;

    // Send Init
    sendJSON("init", "", 0, "Z0", "Loaded: " + name, "Ready to analyze.", false);

    for(const string& pkt : packets) {
        this_thread::sleep_for(chrono::milliseconds(800));
        
        // 1. Log Packet Arrival
        sendJSON("packet_start", pkt, state, (mem.empty() ? "EMPTY" : mem.top()), "Processing " + pkt + "...", "Packet arriving at state q" + to_string(state), false);
        this_thread::sleep_for(chrono::milliseconds(600));

        // 2. Process Logic
        bool attack = false;
        string desc = "";
        string analysis = "";

        // --- PDA LOGIC ENGINE ---
        
        // STATE q0 (Listen)
        if(state == 0) {
            if(pkt == "SYN") { 
                state = 1; hasSession = true; mem.push("S"); 
                desc = "Handshake Valid."; 
                analysis = "Input SYN matches Start Rule. Pushing Session Token.";
            }
            else { 
                state = 3; attack = true; 
                desc = "VIOLATION: No Handshake."; 
                analysis = "Protocol Violation: Traffic must start with SYN.";
            }
        }
        // STATE q1 (Active)
        else if(state == 1) {
            if(pkt == "FIN") {
                if(hasSession) { 
                    state = 2; hasSession = false; mem.pop(); 
                    desc = "Session Closed."; 
                    analysis = "FIN received. Stack has Token. Closing Tunnel.";
                }
            } else {
                if(hasSession) { 
                    state = 1; 
                    desc = "Traffic Authorized."; 
                    analysis = "Valid Traffic inside Secure Tunnel (Token Present).";
                }
                else { 
                    state = 3; attack = true; 
                    desc = "HIJACK ATTEMPT!"; 
                    analysis = "CRITICAL: State q1 active, but Stack is EMPTY. Context missing.";
                }
            }
        }
        // STATE q2 (Closed)
        else if(state == 2) {
            state = 3; attack = true; 
            desc = "INTRUSION DETECTED."; 
            analysis = "Data received after Connection Closed (q2). Implicit Trap.";
        }
        // STATE TRAP
        else { 
            state = 3; attack = true; 
            desc = "Blocked."; 
            analysis = "System in Trap State. Dropping packet.";
        }

        // 3. Send Result
        sendJSON("step", pkt, state, (mem.empty() ? "EMPTY" : mem.top()), desc, analysis, attack);
        
        if(state == 3) break;
    }
    
    sendJSON("done", "", state, "", "Simulation Complete", "End of stream.", false);
}

int main() {
    int id;
    if (cin >> id) {
        runScenario(id);
    }
    return 0;
}