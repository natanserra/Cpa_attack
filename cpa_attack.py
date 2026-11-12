#!/usr/bin/env python3
"""
CPA (Correlation Power Analysis) contra o servidor AES.

Uso:
    python3 cpa_attack.py collect 500      # coleta 500 traces e salva em traces.npz
    python3 cpa_attack.py analyze          # roda a analise de correlacao em traces.npz
    python3 cpa_attack.py collect_and_analyze 500

Requisitos: pip install numpy --break-system-packages
"""
import ast
import os
import socket
import sys
import threading
import time

import numpy as np

HOST = "xebec.cylabacademy.net"
PORT = 10376
OUT_FILE = "traces.npz"

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

HW = [bin(x).count("1") for x in range(256)]

lock = threading.Lock()
results = []  # lista de (plaintext_bytes, trace_list)


def query(hex_pt, timeout=15, retries=5):
    last_err = None
    for attempt in range(retries):
        try:
            return _query_once(hex_pt, timeout)
        except Exception as e:
            last_err = e
            time.sleep(0.3 * (attempt + 1))  # backoff crescente
    raise last_err


def _query_once(hex_pt, timeout):
    with socket.create_connection((HOST, PORT), timeout=timeout) as s:
        f = s.makefile("rwb", buffering=0)
        buf = b""
        while b":" not in buf:
            chunk = f.read(1)
            if not chunk:
                raise RuntimeError("conexao fechada antes do prompt")
            buf += chunk
        f.write((hex_pt + "\n").encode())
        resp = b""
        # le ate o fim da lista (balanceando colchetes)
        started = False
        depth = 0
        while True:
            chunk = f.read(1)
            if not chunk:
                break
            resp += chunk
            if chunk == b"[":
                started = True
                depth += 1
            elif chunk == b"]":
                depth -= 1
                if started and depth == 0:
                    break
        text = resp.decode(errors="ignore")
        start = text.index("[")
        end = text.rindex("]") + 1
        trace = ast.literal_eval(text[start:end])
        return trace


def worker(target_total, stop_flag):
    consecutive_fails = 0
    while True:
        with lock:
            if len(results) >= target_total or stop_flag[0]:
                return
        pt = os.urandom(16)
        hex_pt = pt.hex()
        try:
            trace = query(hex_pt)
            consecutive_fails = 0
        except Exception as e:
            consecutive_fails += 1
            # backoff mais forte se o servidor estiver recusando em sequencia
            wait = min(0.3 * consecutive_fails, 5.0)
            print(f"erro: {e} (aguardando {wait:.1f}s)")
            time.sleep(wait)
            continue
        with lock:
            results.append((pt, trace))
            if len(results) % 5 == 0:
                print(f"coletadas {len(results)} traces")
        time.sleep(0.15)  # pequena pausa entre consultas bem-sucedidas


def save_results():
    if not results:
        print("Nenhuma trace nova coletada, nada para salvar.")
        return
    min_len = min(len(tr) for _, tr in results)
    pts = np.array([list(pt) for pt, _ in results], dtype=np.uint8)
    traces = np.array([tr[:min_len] for _, tr in results], dtype=np.float64)

    if os.path.exists(OUT_FILE):
        old = np.load(OUT_FILE)
        old_pts, old_traces = old["plaintexts"], old["traces"]
        common_len = min(min_len, old_traces.shape[1])
        pts = np.concatenate([old_pts, pts], axis=0)
        traces = np.concatenate(
            [old_traces[:, :common_len], traces[:, :common_len]], axis=0
        )
        print(f"Somando com traces ja existentes em {OUT_FILE}...")

    np.savez_compressed(OUT_FILE, plaintexts=pts, traces=traces)
    print(f"Salvo em {OUT_FILE}: plaintexts {pts.shape}, traces {traces.shape} (total acumulado)")


def collect(n, n_threads=1):
    print(f"Coletando {n} traces com {n_threads} threads (com retry automatico)...")
    t0 = time.time()
    stop_flag = [False]
    threads = []
    for _ in range(n_threads):
        th = threading.Thread(target=worker, args=(n, stop_flag))
        th.daemon = True
        threads.append(th)
        th.start()
    try:
        for th in threads:
            th.join()
    except KeyboardInterrupt:
        print("Interrompido pelo usuario, salvando o que foi coletado ate agora...")
        stop_flag[0] = True
        for th in threads:
            th.join(timeout=2)
    print(f"Coleta terminada em {time.time()-t0:.1f}s, total: {len(results)} traces")
    save_results()


def correlate(hyp, trace_matrix):
    """Correlacao de Pearson entre vetor hyp (N,) e cada coluna de trace_matrix (N,T)."""
    hyp = hyp - hyp.mean()
    tm = trace_matrix - trace_matrix.mean(axis=0, keepdims=True)
    num = hyp @ tm
    den = np.sqrt((hyp**2).sum() * (tm**2).sum(axis=0))
    den[den == 0] = 1e-12
    return num / den


def analyze():
    data = np.load(OUT_FILE)
    pts = data["plaintexts"]  # (N,16)
    traces = data["traces"]   # (N,T)
    N, T = traces.shape
    print(f"Analisando {N} traces de {T} pontos cada...")

    key = [None] * 16
    for byte_i in range(16):
        best_corr = -1
        best_key = None
        pt_col = pts[:, byte_i].astype(np.int64)
        for k in range(256):
            sbox_out = np.array([Sbox[p ^ k] for p in pt_col])
            hyp = np.array([HW[v] for v in sbox_out], dtype=np.float64)
            corr = correlate(hyp, traces)
            max_abs = np.max(np.abs(corr))
            if max_abs > best_corr:
                best_corr = max_abs
                best_key = k
        key[byte_i] = best_key
        print(f"byte {byte_i:2d}: chave = 0x{best_key:02x}  (correlacao = {best_corr:.3f})")

    key_hex = "".join(f"{b:02x}" for b in key)
    print()
    print("CHAVE ENCONTRADA:", key_hex)
    print(f"flag: academy{{{key_hex}}}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "collect":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 300
        collect(n)
    elif cmd == "analyze":
        analyze()
    elif cmd == "collect_and_analyze":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 300
        collect(n)
        analyze()
    else:
        print(__doc__)