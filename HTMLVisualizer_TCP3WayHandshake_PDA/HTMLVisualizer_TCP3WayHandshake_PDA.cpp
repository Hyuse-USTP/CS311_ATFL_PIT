#include <iostream>
#include <fstream>
#include <vector>
#include <string>

using namespace std;

// === DATA STRUCTURES ===
struct Step {
    string packetName;
    string startState; 
    string endState;
    string stackAction; 
    string description; 
    string analysis;    
    bool isAttack;
};

struct Scenario {
    string name;
    vector<Step> steps;
};

// === LOGIC ENGINE ===
Scenario runPDA(string name, vector<string> packets) {
    Scenario scen;
    scen.name = name;
    
    int state = 0; // 0=q0, 1=q1, 2=q2, 3=qtrap
    bool hasSession = false;

    for (const string& pkt : packets) {
        Step s;
        s.packetName = pkt;
        s.startState = (state == 0 ? "q0" : state == 1 ? "q1" : state == 2 ? "q2" : "qtrap");
        s.stackAction = "NONE";
        s.isAttack = false;

        // --- LOGIC ---
        if (state == 0) {
            if (pkt == "SYN") {
                state = 1; hasSession = true;
                s.endState = "q1"; s.stackAction = "PUSH";
                s.description = "Handshake Valid.";
                s.analysis = "Input: SYN. Rule: Transition q0->q1. Action: PUSH Session Token.";
            } else {
                state = 3; s.endState = "qtrap"; s.isAttack = true;
                s.description = "VIOLATION: No Handshake.";
                s.analysis = "Input: " + pkt + ". Error: Protocol demands SYN first. Rejected.";
            }
        }
        else if (state == 1) {
            if (pkt == "FIN") {
                if (hasSession) {
                    state = 2; hasSession = false;
                    s.endState = "q2"; s.stackAction = "POP";
                    s.description = "Session Closed.";
                    s.analysis = "Input: FIN. Stack Check: OK. Action: POP Token, Move to q2.";
                }
            } else {
                if (hasSession) {
                    state = 1; s.endState = "q1";
                    s.description = "Traffic Authorized.";
                    s.analysis = "Input: " + pkt + ". Stack Check: OK (Token Present). Tunnel Active.";
                } else {
                    state = 3; s.endState = "qtrap"; s.isAttack = true;
                    s.description = "HIJACK ATTEMPT!";
                    s.analysis = "CRITICAL: State is q1, but Stack is EMPTY. Session ID missing.";
                }
            }
        }
        else if (state == 2) {
            state = 3; s.endState = "qtrap"; s.isAttack = true;
            s.description = "INTRUSION DETECTED.";
            s.analysis = "State: q2 (Closed). Event: '" + pkt + "'. Result: No transition allows Data here. Default -> TRAP.";
        }
        else {
            state = 3; s.endState = "qtrap"; s.isAttack = true;
            s.description = "Blocked.";
            s.analysis = "System in TRAP state. Traffic dropped.";
        }

        scen.steps.push_back(s);
        if (state == 3) break; 
    }
    return scen;
}

// === HTML GENERATOR ===
void generateDashboard(const vector<Scenario>& scenarios) {
    ofstream f("network_dashboard.html");
    
    f << R"HTML(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PDA Protocol Analyzer</title>
    <style>
        body { background-color: #121212; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; display: flex; flex-direction: column; align-items: center; padding: 20px; }
        
        /* LAYOUT */
        #container { display: flex; gap: 20px; margin-top: 20px; }
        #controls { width: 240px; display: flex; flex-direction: column; gap: 10px; }
        #display-area { position: relative; width: 700px; height: 550px; background: #1e1e1e; border: 2px solid #333; border-radius: 10px; overflow: hidden; box-shadow: 0 0 20px rgba(0,0,0,0.5); }

        /* BUTTONS */
        button { padding: 12px; background: #333; color: white; border: 1px solid #555; cursor: pointer; border-radius: 5px; font-weight: bold; text-align: left; transition: 0.2s;}
        button:hover { border-color: #00e5ff; }
        button.active { background: #00e5ff; color: black; }
        
        /* PLAYBACK BUTTONS */
        button.run-btn { background: #00c853; color: black; text-align: center; width: 100%; margin-bottom: 5px;}
        button.play-btn { background: #9c27b0; color: white; text-align: center; width: 100%; margin-bottom: 10px; border-color: #ce93d8;}
        button.play-btn:hover { background: #ba68c8; }

        /* TIMELINE */
        .control-panel { margin-top: 20px; padding-top: 20px; border-top: 1px solid #444; }
        #step-counter { font-family: monospace; color: #00e5ff; text-align: center; display: block; margin-bottom: 5px; font-size: 14px;}

        /* SLIDER STYLING (CROSS-BROWSER) */
        input[type=range] { -webkit-appearance: none; width: 100%; background: transparent; margin: 10px 0; }
        input[type=range]:focus { outline: none; }
        input[type=range]::-webkit-slider-runnable-track { width: 100%; height: 6px; cursor: pointer; background: #555; border-radius: 3px; }
        input[type=range]::-webkit-slider-thumb { height: 18px; width: 18px; border-radius: 50%; background: #00e5ff; cursor: pointer; -webkit-appearance: none; margin-top: -6px; box-shadow: 0 0 5px rgba(0,229,255,0.5); }
        input[type=range]::-moz-range-track { width: 100%; height: 6px; cursor: pointer; background: #555; border-radius: 3px; }
        input[type=range]::-moz-range-thumb { height: 18px; width: 18px; border: none; border-radius: 50%; background: #00e5ff; cursor: pointer; box-shadow: 0 0 5px rgba(0,229,255,0.5); }

        /* ANALYSIS BOX */
        #analysis-box {
            position: absolute; bottom: 0; left: 0; right: 0; height: 120px;
            background: #111; border-top: 2px solid #444; padding: 15px;
            font-family: 'Consolas', monospace; font-size: 13px; color: #aaa; overflow-y: auto;
        }

        /* NODES */
        .node { width: 70px; height: 70px; border-radius: 50%; border: 3px solid #555; position: absolute; display: flex; flex-direction: column; align-items: center; justify-content: center; background: #121212; transition: 0.3s; z-index: 2; font-weight: bold;}
        .node span { font-size: 10px; color: #888; font-weight: normal; }
        #q0 { top: 80px; left: 50px; }
        #q1 { top: 80px; left: 310px; }
        #q2 { top: 80px; left: 570px; }
        #qtrap { top: 250px; left: 310px; border-color: #aa0000; color: #ff5555; background: #220000; }
        
        .active { border-color: #00e5ff; box-shadow: 0 0 20px #00e5ff; background: #003344; color: white;}
        .trap-active { border-color: red; box-shadow: 0 0 30px red; background: #500; color: white;}

        /* VISUAL ELEMENTS */
        .line { position: absolute; background: #333; z-index: 1; }
        .h-line { top: 115px; height: 4px; }
        .v-line { width: 2px; border-left: 2px dashed #444; }
        #line1 { left: 120px; width: 190px; }
        #line2 { left: 380px; width: 190px; }
        #line-trap1 { top: 150px; left: 345px; height: 100px; }
        #line-trap2 { top: 150px; left: 500px; height: 130px; transform: rotate(55deg); transform-origin: top left; border-left: 2px dashed #622;}

        #packet { position: absolute; top: 100px; left: 50px; padding: 5px 10px; background: #ffea00; color: black; font-weight: bold; border-radius: 4px; opacity: 0; z-index: 10; font-size: 12px; transition: all 1s ease-in-out; box-shadow: 0 0 10px yellow;}

        #stack-container { position: absolute; bottom: 140px; right: 20px; width: 80px; height: 150px; border: 3px solid #777; border-top: 0; display: flex; flex-direction: column-reverse; background: rgba(0,0,0,0.3); align-items: center;}
        .stack-label { position: absolute; bottom: 300px; right: 25px; color: #aaa; font-weight: bold; font-size: 12px;}
        .stack-item { width: 70px; height: 25px; margin-bottom: 2px; border-radius: 3px; display: flex; align-items: center; justify-content: center; font-size: 10px; }
        .base { background: #555; color: #aaa; }
        .token { background: #00e5ff; color: black; }
        
        #alert { position: absolute; top: 20px; width: 100%; text-align: center; color: red; font-size: 24px; font-weight: bold; display: none; text-shadow: 0 0 10px red;}
    </style>
</head>
<body>
    <h1 style="color:#00e5ff">PDA NETWORK VISUALIZER</h1>
    
    <div id="container">
        <div id="controls">
            <h3 style="color:#aaa; margin:0">SCENARIOS</h3>
)HTML";

    for (int i = 0; i < scenarios.size(); i++) {
        f << "<button onclick=\"loadScenario(" << i << ")\">" << (i+1) << ". " << scenarios[i].name << "</button>\n";
    }

    f << R"HTML(
            <div class="control-panel">
                <span id="step-counter">Step: 0 / 0</span>
                <input type="range" id="timeline" min="0" max="0" value="0" step="1" oninput="scrub(this.value)">
                <br><br>
                <button class="play-btn" id="btn-play" onclick="togglePlay()">AUTO PLAY</button>
                <button class="run-btn" onclick="playNext()">STEP FORWARD >></button>
                <button onclick="resetSim()">RESET</button>
            </div>
        </div>

        <div id="display-area">
            <div id="alert">INTRUSION DETECTED</div>

            <div id="q0" class="node">q0<span>Listen</span></div>
            <div id="q1" class="node">q1<span>Active</span></div>
            <div id="q2" class="node">q2<span>Closed</span></div>
            <div id="qtrap" class="node">TRAP<span>Reject</span></div>

            <div id="line1" class="line h-line"></div>
            <div id="line2" class="line h-line"></div>
            <div id="line-trap1" class="line v-line"></div>
            <div id="line-trap2" class="line v-line"></div>
            <div id="packet">DATA</div>
            <div class="stack-label">STACK MEMORY</div>
            <div id="stack-container">
                <div class="stack-item base">Z0</div>
            </div>

            <div id="analysis-box">
                <span style="color:#00e5ff; font-weight:bold">ANALYSIS LOG:</span>
                <div id="analysis-text">Select a scenario...</div>
            </div>
        </div>
    </div>

<script>
    const scenarios = [
)HTML";

    for (const auto& scen : scenarios) {
        f << "{ name: \"" << scen.name << "\", steps: [";
        for (const auto& step : scen.steps) {
            f << "{ pkt: \"" << step.packetName << "\", start: \"" << step.startState << "\", end: \"" << step.endState << "\", action: \"" << step.stackAction << "\", desc: \"" << step.description << "\", analysis: \"" << step.analysis << "\", attack: " << (step.isAttack ? "true" : "false") << "},";
        }
        f << "]},\n";
    }

    f << R"HTML(
    ];

    let currentScenario = null;
    let stepIndex = 0;
    let isAnimating = false;
    let playInterval = null;

    const els = {
        q0: document.getElementById('q0'), q1: document.getElementById('q1'),
        q2: document.getElementById('q2'), qtrap: document.getElementById('qtrap'),
        pkt: document.getElementById('packet'), stack: document.getElementById('stack-container'),
        analysis: document.getElementById('analysis-text'), alert: document.getElementById('alert'),
        timeline: document.getElementById('timeline'), counter: document.getElementById('step-counter'),
        btnPlay: document.getElementById('btn-play')
    };

    function loadScenario(idx) {
        stopPlay();
        currentScenario = scenarios[idx];
        stepIndex = 0;
        els.timeline.max = currentScenario.steps.length;
        els.timeline.value = 0;
        updateCounter();
        
        resetVisuals();
        els.analysis.innerHTML = "Loaded: " + currentScenario.name + "<br>Ready to analyze.";
        
        document.querySelectorAll('#controls button').forEach((b, i) => {
             b.classList.remove('active');
        });
        document.querySelectorAll('#controls button')[idx].classList.add('active');
    }

    function resetVisuals() {
        els.q0.className = 'node active'; els.q1.className = 'node';
        els.q2.className = 'node'; els.qtrap.className = 'node';
        els.pkt.style.opacity = 0; els.pkt.style.left = '50px'; els.pkt.style.top = '100px';
        els.alert.style.display = 'none';
        els.stack.innerHTML = '<div class="stack-item base">Z0</div>';
    }

    function updateCounter() {
        els.counter.innerText = "Step: " + stepIndex + " / " + currentScenario.steps.length;
    }

    // --- PLAYBACK CONTROLS ---
    function togglePlay() {
        if (playInterval) {
            stopPlay();
        } else {
            startPlay();
        }
    }

    function startPlay() {
        // If already at end, reset to start
        if(stepIndex >= currentScenario.steps.length) {
            resetSim();
        }
        
        els.btnPlay.innerText = "PAUSE";
        els.btnPlay.style.background = "#ff9800"; // Orange
        
        playInterval = setInterval(() => {
            if(stepIndex >= currentScenario.steps.length) {
                stopPlay();
            } else if (!isAnimating) {
                playNext();
            }
        }, 1200); // 1.2s delay (allows 0.8s animation + buffer)
        
        // Trigger first step immediately
        if(!isAnimating) playNext();
    }

    function stopPlay() {
        if(playInterval) {
            clearInterval(playInterval);
            playInterval = null;
        }
        els.btnPlay.innerText = "AUTO PLAY";
        els.btnPlay.style.background = "#9c27b0"; // Purple
    }

    function scrub(val) {
        stopPlay(); // Stop if dragging
        stepIndex = parseInt(val);
        updateCounter();
        isAnimating = false; 
        
        resetVisuals();
        
        if (stepIndex === 0) {
            els.analysis.innerHTML = "Reset to start.";
            return;
        }

        let lastState = 'q0';
        
        for(let i = 0; i < stepIndex; i++) {
            const step = currentScenario.steps[i];
            
            if(step.action === 'PUSH') {
                const t = document.createElement('div'); t.className = 'stack-item token'; t.innerText = 'SESSION';
                els.stack.appendChild(t);
            } else if(step.action === 'POP') {
                const tokens = document.querySelectorAll('.token');
                if(tokens.length > 0) tokens[tokens.length-1].remove();
            }
            lastState = step.end;
        }

        const currentStep = currentScenario.steps[stepIndex - 1];
        
        els.q0.classList.remove('active'); els.q1.classList.remove('active');
        els.q2.classList.remove('active'); els.qtrap.classList.remove('active');
        
        if(lastState === 'q1') els.q1.classList.add('active');
        else if(lastState === 'q2') els.q2.classList.add('active');
        else if(lastState === 'qtrap') {
            els.qtrap.classList.add('trap-active');
            els.alert.style.display = 'block';
        } else {
            els.q0.classList.add('active');
        }

        els.analysis.innerHTML = "<span style='color:white'>History:</span> Jumped to Step " + stepIndex + ".<br>" + 
                                 "<span style='color:#00e5ff'>Last Event:</span> " + currentStep.desc;
    }

    function playNext() {
        if (!currentScenario || stepIndex >= currentScenario.steps.length || isAnimating) return;
        
        stepIndex++;
        els.timeline.value = stepIndex;
        updateCounter();

        const step = currentScenario.steps[stepIndex - 1];
        isAnimating = true;

        // Visuals
        els.pkt.innerText = step.pkt;
        els.pkt.style.transition = 'none';
        els.pkt.style.backgroundColor = step.attack ? '#ff3d00' : '#ffea00';
        els.pkt.style.color = step.attack ? 'white' : 'black';
        
        if(step.start === 'q0') { els.pkt.style.left = '50px'; els.pkt.style.top = '100px'; }
        if(step.start === 'q1') { els.pkt.style.left = '310px'; els.pkt.style.top = '100px'; }
        if(step.start === 'q2') { els.pkt.style.left = '570px'; els.pkt.style.top = '100px'; }
        els.pkt.style.opacity = 1;
        void els.pkt.offsetWidth; 

        els.pkt.style.transition = 'all 0.8s cubic-bezier(0.25, 1, 0.5, 1)';
        
        if(step.end === 'q1') els.pkt.style.left = '310px';
        else if(step.end === 'q2') els.pkt.style.left = '570px';
        else if(step.end === 'qtrap') { els.pkt.style.left = '310px'; els.pkt.style.top = '275px'; }

        els.analysis.innerHTML = "<span style='color:white'>Processing:</span> " + step.pkt + "<br><span style='color:#00e5ff'>Theory:</span> " + step.analysis;

        setTimeout(() => {
            els.q0.classList.remove('active'); els.q1.classList.remove('active');
            els.q2.classList.remove('active');

            if(step.end === 'q1') els.q1.classList.add('active');
            else if(step.end === 'q2') els.q2.classList.add('active');
            else if(step.end === 'qtrap') {
                els.qtrap.classList.add('trap-active');
                els.alert.style.display = 'block';
                isAnimating = false;
                return;
            }

            if(step.action === 'PUSH') {
                const t = document.createElement('div'); t.className = 'stack-item token'; t.innerText = 'SESSION';
                els.stack.appendChild(t);
            } else if(step.action === 'POP') {
                const tokens = document.querySelectorAll('.token');
                if(tokens.length > 0) tokens[tokens.length-1].remove();
            }

            els.pkt.style.opacity = 0;
            isAnimating = false;
        }, 800);
    }

    function resetSim() { 
        stopPlay();
        stepIndex = 0; 
        els.timeline.value = 0;
        updateCounter();
        resetVisuals(); 
        els.analysis.innerHTML = "Reset complete."; 
    }
    
    // AUTO LOAD
    loadScenario(0); 
</script>
</body>
</html>
)HTML";
    f.close();
    cout << "Dashboard Generated: network_dashboard.html" << endl;
}

int main() {
    vector<Scenario> all;
    all.push_back(runPDA("Web Browsing (Safe)", {"SYN", "ACK", "HTTP_GET", "FIN"}));
    all.push_back(runPDA("SSH Session (Safe)", {"SYN", "ACK", "SSH_KEY", "ENCRYPTED_DATA", "FIN"}));
    all.push_back(runPDA("Session Hijack (Attack)", {"SYN", "ACK", "SSH_KEY", "FIN", "ROOT_CMD"}));
    all.push_back(runPDA("Nmap Scan (Attack)", {"FIN"}));

    generateDashboard(all);
    return 0;
}