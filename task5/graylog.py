"""
SIEM Graylog Emulator (single-file Python program)

Features:
- Simulates Graylog-style ingestion (also exposes a GELF-like HTTP endpoint)
- Generates sample Linux auth/connection logs in real-time
- Ingests & preprocesses logs, stores events in-memory
- Implements 3 alert rules:
    1) Failed SSH login bursts (>=5 fails per IP within 60s)
    2) Port scan detection (>=10 distinct ports from same IP within 30s)
    3) IP anomaly/spike detection (>100 events from same IP within 60s or blacklisted IP)
- Serves a mini dashboard (Flask + Chart.js) with real-time updates via Server-Sent Events (SSE)

Run:
    pip install flask
    python siem_graylog_emulator.py

Open http://127.0.0.1:5000 in your browser.

Notes:
- This is an emulator to satisfy the exercise using a single Python program. It shows how you would
  adapt to Graylog (e.g., by sending logs to Graylog's GELF HTTP input); a /gelf endpoint is included
  to accept GELF-like POSTs.

"""

from flask import Flask, Response, render_template_string, request, jsonify
import threading, time, re, json, random, datetime, queue
from collections import defaultdict, deque

app = Flask(__name__)

#########################
# Configuration
#########################
LOG_FILE = 'sample_syslog.log'
SAMPLE_GENERATION_INTERVAL = 0.5  # seconds between generated lines
KEEP_EVENTS_SECONDS = 3600  # how long to keep in-memory events

# Alert thresholds
FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW = 60  # seconds
PORTSCAN_PORTS_THRESHOLD = 10
PORTSCAN_WINDOW = 30
SPIKE_THRESHOLD = 100
SPIKE_WINDOW = 60

# Blacklist for IP anomaly rule (example)
BLACKLISTED_IPS = set(['203.0.113.55'])

#########################
# In-memory stores
#########################
events = deque()  # (timestamp, event_dict)
alerts = deque(maxlen=1000)  # recent alerts
stats_lock = threading.Lock()
subscribers = []  # SSE clients

# Helpful structures for rules
failed_login_tracker = defaultdict(deque)  # ip -> deque(timestamps)
port_activity = defaultdict(lambda: defaultdict(set))  # ip -> {window_start: set(ports)}
ip_event_tracker = defaultdict(deque)  # ip -> deque(timestamps)

# Queue for parsed events to push to SSE
event_queue = queue.Queue()

#########################
# Log line generator (simulates Linux logs)
#########################
USERS = ['alice','bob','carol','dave']
PORTS = list(range(20,1025))

AUTH_FAILS = [
    "Failed password for invalid user {user} from {ip} port {port} ssh2",
    "Failed password for {user} from {ip} port {port} ssh2",
]
AUTH_SUCC = [
    "Accepted password for {user} from {ip} port {port} ssh2",
]
CONN = [
    "Connection from {ip} port {port}",
    "Connection attempt from {ip} to port {port}",
]

IP_POOL = [f'192.0.2.{i}' for i in range(1,60)] + ['203.0.113.55']  # include a blacklisted IP

log_line_template = "{ts} {host} sshd[{pid}]: {msg}\n"


def generate_sample_lines(stop_event):
    host = 'emulator-host'
    pid = 1000
    while not stop_event.is_set():
        ts = datetime.datetime.utcnow().strftime('%b %d %H:%M:%S')
        pid += 1
        ip = random.choice(IP_POOL)
        port = random.choice(PORTS)
        choice = random.random()
        if choice < 0.12:
            msg = random.choice(AUTH_FAILS).format(user=random.choice(USERS), ip=ip, port=port)
        elif choice < 0.18:
            msg = random.choice(AUTH_SUCC).format(user=random.choice(USERS), ip=ip, port=port)
        else:
            msg = random.choice(CONN).format(ip=ip, port=port)
        line = log_line_template.format(ts=ts, host=host, pid=pid, msg=msg)
        with open(LOG_FILE, 'a') as f:
            f.write(line)
        time.sleep(SAMPLE_GENERATION_INTERVAL)

#########################
# Tail & parse log file
#########################

auth_fail_re = re.compile(r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)')
auth_succ_re = re.compile(r'Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)')
conn_re = re.compile(r'(?:Connection|Connection attempt) (?:from )?(?P<ip>\d+\.\d+\.\d+\.\d+)(?: to port (?P<port>\d+)| port (?P<port2>\d+))')


def tail_and_ingest(stop_event):
    # Ensure file exists
    open(LOG_FILE,'a').close()
    with open(LOG_FILE,'r') as f:
        # go to end
        f.seek(0,2)
        while not stop_event.is_set():
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            parsed = parse_line(line)
            if parsed:
                ingest_event(parsed)


def parse_line(line):
    # Very simple parser
    ts_str = ''
    try:
        # Split timestamp from message (first 15 chars like 'Dec  9 12:34:56')
        ts_str = line[:15]
        msg = line[16:].strip()
    except Exception:
        msg = line.strip()
    now = datetime.datetime.utcnow()

    m = auth_fail_re.search(msg)
    if m:
        return {'type':'auth_fail','user':m.group('user'),'ip':m.group('ip'),'port':int(m.group('port')),'raw':msg,'ts':now.timestamp()}
    m = auth_succ_re.search(msg)
    if m:
        return {'type':'auth_succ','user':m.group('user'),'ip':m.group('ip'),'port':int(m.group('port')),'raw':msg,'ts':now.timestamp()}
    m = conn_re.search(msg)
    if m:
        port = m.group('port') or m.group('port2')
        return {'type':'conn','ip':m.group('ip'),'port':int(port),'raw':msg,'ts':now.timestamp()}
    return {'type':'unknown','raw':msg,'ts':now.timestamp()}

#########################
# Ingest and rules
#########################


def ingest_event(evt):
    with stats_lock:
        events.append((evt['ts'], evt))
        # clean old
        cutoff = time.time() - KEEP_EVENTS_SECONDS
        while events and events[0][0] < cutoff:
            events.popleft()
    event_queue.put(evt)
    apply_alert_rules(evt)


def apply_alert_rules(evt):
    now = time.time()
    ip = evt.get('ip')
    etype = evt.get('type')

    # Track for spike rule
    if ip:
        dq = ip_event_tracker[ip]
        dq.append(now)
        # remove old
        while dq and dq[0] < now - SPIKE_WINDOW:
            dq.popleft()
        if len(dq) > SPIKE_THRESHOLD:
            raise_alert('IP_SPIKE', ip, f'{len(dq)} events in last {SPIKE_WINDOW}s')
        if ip in BLACKLISTED_IPS:
            raise_alert('IP_BLACKLIST', ip, f'IP is blacklisted')

    # Failed login rule
    if etype == 'auth_fail' and ip:
        fq = failed_login_tracker[ip]
        fq.append(now)
        while fq and fq[0] < now - FAILED_LOGIN_WINDOW:
            fq.popleft()
        if len(fq) >= FAILED_LOGIN_THRESHOLD:
            raise_alert('BRUTE_FORCE', ip, f'{len(fq)} failed logins within {FAILED_LOGIN_WINDOW}s')

    # Port scan rule (track distinct ports within window)
    if etype == 'conn' and ip:
        # keep a timestamped list of ports in a deque for sliding window
        # We'll use a simple structure: port_activity[ip] = {'ports': deque of (ts,port)}
        if 'ports_deque' not in port_activity[ip]:
            port_activity[ip]['ports_deque'] = deque()
        pdq = port_activity[ip]['ports_deque']
        pdq.append((now, evt.get('port')))
        # remove old
        while pdq and pdq[0][0] < now - PORTSCAN_WINDOW:
            pdq.popleft()
        distinct_ports = set(p for t,p in pdq)
        if len(distinct_ports) >= PORTSCAN_PORTS_THRESHOLD:
            raise_alert('PORT_SCAN', ip, f'{len(distinct_ports)} distinct ports within {PORTSCAN_WINDOW}s')


def raise_alert(rule, ip, description):
    alert = {'ts': time.time(), 'rule': rule, 'ip': ip, 'desc': description}
    with stats_lock:
        alerts.appendleft(alert)
    # push to SSE / event queue
    event_queue.put({'alert': alert})
    print(f"ALERT: {rule} - {ip} - {description}")

#########################
# SSE endpoint for real-time updates
#########################

def event_stream():
    # generator that yields Server-Sent Events
    q = queue.Queue()
    subscribers.append(q)
    try:
        while True:
            item = q.get()
            yield f'data: {json.dumps(item)}\n\n'
    except GeneratorExit:
        subscribers.remove(q)


def sse_dispatcher():
    # read from global event_queue and dispatch to subscribers
    while True:
        item = event_queue.get()
        # push to all subscribers
        for s in list(subscribers):
            try:
                s.put(item, block=False)
            except Exception:
                pass

#########################
# Flask routes (dashboard + APIs)
#########################

DASH_HTML = '''
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>SIEM Mini Dashboard (Graylog Emulator)</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>body{font-family: Arial, Helvetica, sans-serif; margin:20px} .col{display:inline-block;vertical-align:top;margin-right:20px} .card{border:1px solid #ddd;padding:10px;border-radius:6px;min-width:300px}</style>
  </head>
  <body>
    <h2>SIEM Mini Dashboard (Graylog Emulator)</h2>
    <div>
      <div class="col card">
        <h4>Recent Alerts</h4>
        <ul id="alerts"></ul>
      </div>
      <div class="col card">
        <h4>Top IPs (events count)</h4>
        <canvas id="topIpsChart" width="400" height="300"></canvas>
      </div>
      <div class="col card">
        <h4>Events / sec (last minute)</h4>
        <canvas id="eventsChart" width="400" height="300"></canvas>
      </div>
    </div>

    <h4>Recent Raw Events</h4>
    <pre id="raw" style="height:200px;overflow:auto;border:1px solid #ddd;padding:10px"></pre>

    <script>
      let alertsEl = document.getElementById('alerts');
      let rawEl = document.getElementById('raw');

      const topIpsCtx = document.getElementById('topIpsChart').getContext('2d');
      const eventsCtx = document.getElementById('eventsChart').getContext('2d');

      let topIpsChart = new Chart(topIpsCtx, {type:'bar',data:{labels:[],datasets:[{label:'Events',data:[]}]},options:{animation:false}});
      let eventsChart = new Chart(eventsCtx, {type:'line',data:{labels:[],datasets:[{label:'events/sec',data:[]}]},options:{animation:false}});

      const evtSrc = new EventSource('/stream');
      evtSrc.onmessage = function(e){
        let obj = JSON.parse(e.data);
        if(obj.alert){
          let a = obj.alert;
          let li = document.createElement('li');
          li.textContent = new Date(a.ts*1000).toLocaleString()+" | "+a.rule+" | "+a.ip+" | "+a.desc;
          alertsEl.prepend(li);
        } else {
          // treat as event
          rawEl.textContent = JSON.stringify(obj)+"\n"+rawEl.textContent;
        }
        // refresh summaries
        fetch('/summary').then(r=>r.json()).then(updateCharts);
      }

      function updateCharts(data){
        topIpsChart.data.labels = data.top_ips.labels;
        topIpsChart.data.datasets[0].data = data.top_ips.data;
        topIpsChart.update();

        eventsChart.data.labels = data.events.series;
        eventsChart.data.datasets[0].data = data.events.data;
        eventsChart.update();
      }

      // initial load
      fetch('/summary').then(r=>r.json()).then(updateCharts);
    </script>
  </body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(DASH_HTML)

@app.route('/stream')
def stream():
    return Response(event_stream(), mimetype='text/event-stream')

@app.route('/summary')
def summary():
    # produce top IPs and events/sec for last 60s
    now = time.time()
    cutoff = now - 60
    ip_counts = defaultdict(int)
    with stats_lock:
        for ts,evt in events:
            if ts >= cutoff:
                ip = evt.get('ip')
                if ip:
                    ip_counts[ip]+=1
    top = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    labels = [ip for ip,_ in top]
    data = [c for _,c in top]
    # events per second series for last 60 seconds
    series = []
    datapoints = []
    for i in range(60):
        t0 = now - (60 - i)
        t1 = t0 + 1
        cnt = 0
        with stats_lock:
            for ts,evt in events:
                if ts >= t0 and ts < t1:
                    cnt += 1
        series.append(time.strftime('%H:%M:%S', time.gmtime(t0)))
        datapoints.append(cnt)
    return jsonify({'top_ips':{'labels':labels,'data':data},'events':{'series':series,'data':datapoints}})

@app.route('/alerts')
def get_alerts():
    with stats_lock:
        return jsonify(list(alerts))

@app.route('/gelf', methods=['POST'])
def gelf_input():
    # Accepts a GELF-like JSON payload and ingests as event
    payload = request.get_json(force=True)
    # Minimal mapping
    evt = {'type':'gelf','raw':payload,'ts':time.time()}
    # try to extract ip/port
    ip = payload.get('host') or payload.get('_ip') or payload.get('short_message')
    if isinstance(ip, str) and re.match(r'\d+\.\d+\.\d+\.\d+', ip):
        evt['ip'] = ip
    ingest_event(evt)
    return jsonify({'status':'ok'})

@app.route('/send_sample', methods=['POST'])
def send_sample():
    # Accept a log line via POST for convenience
    content = request.get_json(force=True)
    line = content.get('line')
    if not line:
        return jsonify({'error':'no line provided'}),400
    parsed = parse_line(line+'\n')
    if parsed:
        ingest_event(parsed)
        return jsonify({'status':'ok'})
    return jsonify({'status':'ignored'})

#########################
# Startup & threads
#########################

stop_event = threading.Event()

# Flask 3.x removed before_first_request → start threads before app.run()
pass  # placeholder; threads start in __main__


if __name__ == '__main__':
    print('Starting SIEM Graylog Emulator...')
    print('Writing sample log to', LOG_FILE)

    # Start background threads BEFORE Flask starts (Flask 3.x compatible)
    t_gen = threading.Thread(target=generate_sample_lines, args=(stop_event,), daemon=True)
    t_gen.start()
    t_tail = threading.Thread(target=tail_and_ingest, args=(stop_event,), daemon=True)
    t_tail.start()
    t_sse = threading.Thread(target=sse_dispatcher, daemon=True)
    t_sse.start()

    try:
        app.run(debug=True, threaded=True, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        stop_event.set()
        print('Shutting down...')(debug=True, threaded=True, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        stop_event.set()
        print('Shutting down...')
