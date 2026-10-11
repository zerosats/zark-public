"""Shared subprocess accounting for real proof qualification."""
import hashlib,json,os,re,subprocess,sys,time

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fields(data):
    assert len(data) % 32 == 0, "non-field-aligned encoding"
    return ["0x" + data[i:i + 32].hex() for i in range(0, len(data), 32)]


def toml(values):
    return "\n".join(k + " = " + json.dumps(
        [str(x) for x in v] if isinstance(v, list) else str(v)
    ) for k, v in values.items()) + "\n"


class Qualification:
    def run(self, label, command, allowed_failure=False):
        log = self.logs / (label + ".log")
        # Native `time` measures each child separately; resource.getrusage would
        # only report the largest child seen so far in this Python process.
        timed = ["/usr/bin/time", "-l" if sys.platform == "darwin" else "-v"] + command
        started = time.monotonic()
        result = subprocess.run(timed, cwd=self.root, env=self.environment,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        elapsed = time.monotonic() - started
        log.write_text(result.stdout)
        peak = re.search(r"(\d+)\s+maximum resident set size", result.stdout)
        if sys.platform != "darwin":
            peak = re.search(r"Maximum resident set size \(kbytes\): (\d+)", result.stdout)
        entry = {"label": label, "argv": command, "exit_code": result.returncode,
                 "elapsed_seconds": round(elapsed, 4), "log": str(log.relative_to(self.root))}
        if peak:
            entry["peak_rss_bytes"] = int(peak[1]) * (1 if sys.platform == "darwin" else 1024)
        self.commands.append(entry)
        (self.work / "commands.json").write_text(json.dumps(self.commands, indent=2) + "\n")
        print(f"{label}: exit={result.returncode}, {elapsed:.3f}s", flush=True)
        if result.returncode and not allowed_failure:
            raise RuntimeError(f"{label} failed: {result.stdout[-6000:]}")
        return result

