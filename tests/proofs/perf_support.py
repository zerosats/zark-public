"""Same 100 ms process-tree sampling used by the isolated v8 comparison.

Wall time includes the final polling interval (at most about 100 ms plus ps
overhead). Native time reports per-command peak RSS independently of sampling.
"""
import hashlib,re,subprocess,sys,time

def streamed_digest(path):
    h=hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda:source.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()

def process_tree_rss(root_pid):
    rows=subprocess.check_output(['/bin/ps','-axo','pid=,ppid=,rss='],text=True)
    processes={}
    for row in rows.splitlines():
        pid,parent,rss=map(int,row.split());processes[pid]=(parent,rss*1024)
    children={root_pid}
    while True:
        expanded=children|{pid for pid,(parent,_) in processes.items() if parent in children}
        if expanded==children:break
        children=expanded
    return sum(processes.get(pid,(0,0))[1] for pid in children)

def measure(command,cwd,log,env):
    timed=['/usr/bin/time','-l' if sys.platform=='darwin' else '-v']+list(map(str,command))
    start=time.monotonic();peak=0;samples=0
    with log.open('w') as output:
        child=subprocess.Popen(timed,cwd=cwd,env=env,stdout=output,stderr=subprocess.STDOUT,text=True)
        while child.poll() is None:
            peak=max(peak,process_tree_rss(child.pid));samples+=1;time.sleep(0.1)
        status=child.wait()
    row=dict(argv=list(map(str,command)),exit_code=status,elapsed_seconds=round(time.monotonic()-start,4),
        sampled_process_tree_peak_rss_bytes=peak,rss_samples=samples,rss_sample_interval_seconds=0.1,log=str(log))
    output=log.read_text()
    threads=re.search(r'num threads:\s*(\d+)',output)
    if threads:row['reported_backend_threads']=int(threads[1])
    patterns=[(r'(\d+)\s+maximum resident set size','peak_rss_bytes'),(r'(\d+)\s+peak memory footprint','peak_memory_footprint_bytes')]
    if sys.platform!='darwin':patterns=[(r'Maximum resident set size \(kbytes\): (\d+)','peak_rss_bytes')]
    for pattern,key in patterns:
        match=re.search(pattern,output)
        if match:row[key]=int(match[1])*(1024 if sys.platform!='darwin' else 1)
    assert status==0,str(command)+': '+output[-6000:]
    return row
