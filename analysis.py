import pandas as pd
import numpy as np
import io
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

def calculate_time_diffs(datetime_series):
    diffs = datetime_series.diff().dt.total_seconds().dropna().tolist()
    return [d + 86400 if d < 0 else d for d in diffs]

def analyze_session():
    # Looks for the CSV in the exact same folder where this Python script is executed
    file_path = 'head_metrics.csv'
    
    print(f"Reading {file_path} and isolating the latest session...\n")
    
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: Could not find '{file_path}'. Ensure the CSV and this script are in the same folder!")
        return

    # Dynamically locate the most recent session
    start_idx = -1
    for i in range(len(lines) - 1, -1, -1):
        if "--- HEAD REQUEST BASELINE @" in lines[i]:
            start_idx = i + 1 
            break

    if start_idx == -1:
        print("Error: Could not find any valid session headers in the file.")
        return

    end_idx = len(lines)
    for i in range(start_idx + 1, len(lines)):
        if lines[i].startswith("--- "):
            end_idx = i
            break

    session_lines = lines[start_idx:end_idx]
    csv_data = io.StringIO(''.join(session_lines))
    df = pd.read_csv(csv_data)
    
    df.columns = df.columns.str.strip()
    df['Cloudflare Cache Status'] = df['Cloudflare Cache Status'].astype(str).str.strip()
    df['Datetime'] = pd.to_datetime(df['Time Request Sent'], format='%H:%M:%S.%f', errors='coerce')
    
    numeric_cols = ['DNS Lookup Time (ms)', 'TCP Handshake Time (ms)', 'TLS Handshake Time (ms)', 'Time to First Byte (ms)']
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce')
        # --- BUG FIX: Clamp any negative telemetry values to zero before analysis ---
        # This addresses libcurl/time precision issues producing negative handshake times.
        df[col] = df[col].clip(lower=0.0)

    total_calls = len(df)
    
    if total_calls > 1:
        total_time_seconds = (df['Datetime'].iloc[-1] - df['Datetime'].iloc[0]).total_seconds()
        if total_time_seconds < 0: total_time_seconds += 86400 
        effective_poll_rate_ms = (total_time_seconds / total_calls) * 1000
    else:
        effective_poll_rate_ms = 0

    print("==================================================")
    print(f"         COMPLETE SESSION ANALYSIS REPORT         ")
    print("==================================================\n")
    print(f"Total Network Calls Analyzed: {total_calls}")
    print(f"Effective Polling Interval (w/ Overhead): {effective_poll_rate_ms:.2f} ms per call\n")

    # --- METRIC 1: CLOUDFLARE KEEP-ALIVE TERMINATIONS (Fixed Noise Handling) ---
    
    # --- BUG FIX: Threshold adjusted to 1.0ms to ignore microsecond noise ---
    # Values under 1ms are typical of a warm connection; values over 1ms represent a true connection setup.
    handshake_threshold = 1.0 # 1.0 ms
    renegotiation_indices = df.index[
        (df['DNS Lookup Time (ms)'] > handshake_threshold) |
        (df['TCP Handshake Time (ms)'] > handshake_threshold) |
        (df['TLS Handshake Time (ms)'] > handshake_threshold)
    ].tolist()
    
    renegotiations = df.iloc[renegotiation_indices].copy()
    
    print(f"[1] CLOUDFLARE KEEP-ALIVE TERMINATIONS")
    print(f"    - TCP Connections Severed: {len(renegotiations)}")
    
    if len(renegotiation_indices) > 1:
        diffs_reneg = calculate_time_diffs(renegotiations['Datetime'])
        requests_between_drops = np.diff(renegotiation_indices)
        
        avg_reqs = np.mean(requests_between_drops)
        std_reqs = np.std(requests_between_drops)
        actual_avg_time = np.mean(diffs_reneg)
        estimated_time = (avg_reqs * effective_poll_rate_ms) / 1000
        time_variance = abs(actual_avg_time - estimated_time)

        print(f"    - Avg Requests Before Termination: {avg_reqs:.0f} requests (StdDev: ±{std_reqs:.0f})")
        print(f"    - Estimated Time Until Cutoff: {estimated_time:.2f} seconds")
        print(f"    - Actual Time Until Cutoff: {actual_avg_time:.2f} seconds")
        print(f"    - Margin of Error: {time_variance:.2f} seconds\n")
        
    print()

    # --- BASELINE SPLIT: PREPARING STATIC VS DYNAMIC ---
    non_new_data = df[df['Is New Data Detected'] == 'NO'].copy()

    # --- METRIC 2: HARD OUTLIER ANALYSIS (>100ms) ---
    outliers_legacy = non_new_data[non_new_data['Time to First Byte (ms)'] > 100].copy()
    
    # --- BUG FIX: This filter will now populate because DNS noise is clamped ---
    valid_normal_legacy = non_new_data[
        (non_new_data['Time to First Byte (ms)'] <= 100) & 
        (non_new_data['DNS Lookup Time (ms)'] == 0)
    ]
    
    print(f"[2] HARD OUTLIER ANALYSIS (Strictly >100ms)")
    print(f"    - Total Major Spikes: {len(outliers_legacy)}")
            
    # This will now display a number, not NaN.
    avg_ttfb_normal_legacy = valid_normal_legacy['Time to First Byte (ms)'].mean()
    print(f"\n    => UNFILTERED BASELINE PING: {avg_ttfb_normal_legacy:.2f} ms\n")

    # --- METRIC 3: ADAPTIVE NETWORK HEALTH (IQR Method) ---
    q1 = non_new_data['Time to First Byte (ms)'].quantile(0.25)
    q3 = non_new_data['Time to First Byte (ms)'].quantile(0.75)
    iqr = q3 - q1
    outlier_threshold = q3 + (3 * iqr) 
    
    outliers_dynamic = non_new_data[non_new_data['Time to First Byte (ms)'] > outlier_threshold].copy()
    valid_normal_dynamic = non_new_data[non_new_data['Time to First Byte (ms)'] <= outlier_threshold].copy()
    
    outlier_percentage = (len(outliers_dynamic) / total_calls) * 100 if total_calls > 0 else 0

    print(f"[3] ADAPTIVE NETWORK HEALTH (IQR Threshold: >{outlier_threshold:.2f} ms)")
    print(f"    - Total Anomalies Removed: {len(outliers_dynamic)}")
    print(f"    - Network Volatility Score: {outlier_percentage:.2f}% of calls experienced jitter")
    
    avg_normal_dyn = valid_normal_dynamic['Time to First Byte (ms)'].mean()
    std_normal_dyn = valid_normal_dynamic['Time to First Byte (ms)'].std()
    print(f"\n    => TRUE BASELINE PING (Strict IQR): {avg_normal_dyn:.2f} ms (StdDev: ±{std_normal_dyn:.2f} ms)\n")

    # --- METRIC 4: NETWORK PATTERN ANALYZER ---
    # Note: Autocorrelation at microsecond pooling intervals often registers false patterns.
    print(f"[4] NETWORK PATTERN ANALYSIS (Autocorrelation)")
    valid_normal_dynamic['TTFB_Diff'] = valid_normal_dynamic['Time to First Byte (ms)'].diff()
    
    jumps = len(valid_normal_dynamic[valid_normal_dynamic['TTFB_Diff'] > 5.0]) 
    drops = len(valid_normal_dynamic[valid_normal_dynamic['TTFB_Diff'] < -2.0]) 
    
    if valid_normal_dynamic['Time to First Byte (ms)'].std() > 0:
        autocorr = valid_normal_dynamic['Time to First Byte (ms)'].autocorr(lag=1)
    else:
        autocorr = np.nan
    
    print(f"    - Autocorrelation Score: {autocorr:.3f}" if not np.isnan(autocorr) else "    - Autocorrelation Score: N/A (variance is 0)")
    if not np.isnan(autocorr):
        if autocorr > 0.3:
            print("      (Diagnosis: Strong Pattern. Possible device buffering.)")
        elif autocorr < -0.3:
            print("      (Diagnosis: Hard Oscillation. Latency ping-pong effect.)")
        else:
            print("      (Diagnosis: Weak Pattern. Latency changes are natural internet jitter.)")
        
    print(f"    - Micro-Spikes (>5ms variance): {jumps} times")
    print(f"    - Micro-Drops (>2ms variance): {drops} times\n")

    # --- METRIC 5: REQUEST COALESCING & ORIGIN PULL TIMING ---
    new_data = df[df['Is New Data Detected'] == 'YES'].copy()
    if not new_data.empty:
        avg_gross_wait = new_data['Time to First Byte (ms)'].mean()
        net_origin_wait = avg_gross_wait - avg_normal_dyn

        print(f"[5] THE WAITING ROOM (Request Coalescing Metrics):")
        print(f"    - Gross Wait (Total TTFB): {avg_gross_wait:.2f} ms")
        print(f"    - Net Origin Pull Wait (Gross TTFB minus True Baseline Ping): {net_origin_wait:.2f} ms")
        print(f"    - Fastest Recorded Wait: {new_data['Time to First Byte (ms)'].min():.2f} ms")
        print(f"    - Slowest Recorded Wait: {new_data['Time to First Byte (ms)'].max():.2f} ms\n")
    else:
        print("[5] THE WAITING ROOM: No new data drops found during this session.\n")

    # --- METRIC 6: VANGUARD "MISS" ANALYSIS ---
    miss_data = df[df['Cloudflare Cache Status'] == 'MISS'].copy()
    print(f"[6] VANGUARD 'MISS' ANALYSIS (Did we trigger the origin pull?):")
    print(f"    - Total 'MISS' Events Recorded: {len(miss_data)}")
    
    if not miss_data.empty:
        miss_and_new = miss_data[miss_data['Is New Data Detected'] == 'YES']
        print(f"    - Successful Origin Triggers (MISS + YES): {len(miss_and_new)}")
        print(f"    - MISS Latency Avg: {miss_data['Time to First Byte (ms)'].mean():.2f} ms (StdDev: ±{miss_data['Time to First Byte (ms)'].std():.2f} ms)\n")
    else:
        print("    - No MISS events found. (Cache beat you to the edge node!)\n")

    # --- METRIC 7: THE STAMPEDE CORRELATION ---
    print("[7] THE STAMPEDE CORRELATION (Edge Node Load Testing):")
    if not outliers_dynamic.empty and not new_data.empty:
        correlated_outliers = 0
        outlier_times = outliers_dynamic['Datetime'].tolist()
        drop_times = new_data['Datetime'].tolist()

        for out_time in outlier_times:
            for drop_time in drop_times:
                time_diff = (out_time - drop_time).total_seconds()
                if time_diff < -40000: time_diff += 86400
                elif time_diff > 40000: time_diff -= 86400
                if -1.0 <= time_diff <= 3.0:
                    correlated_outliers += 1
                    break
            
        percent_correlated = (correlated_outliers / len(outliers_dynamic)) * 100
        print(f"    - Spikes synchronized with the cache drop (-1s to +3s): {correlated_outliers} ({percent_correlated:.1f}%)")
    else:
        print("    - Not enough data to calculate stampede correlation.")

    # --- METRIC 8: INTERACTIVE GRAPH GENERATION ---
    print("\n[8] GENERATING LATENCY VISUALIZATION...")
    if not non_new_data.empty:
        plt.figure(figsize=(14, 7))
        plt.plot(non_new_data['Datetime'], non_new_data['Time to First Byte (ms)'], color='#1f77b4', linewidth=1.5, alpha=0.8)
        
        plt.title('Network Latency: Time to First Byte (Non-New Data / Cache HITs)', fontsize=14, fontweight='bold')
        plt.xlabel('Time of Request', fontsize=12)
        plt.ylabel('TTFB (ms)', fontsize=12)
        
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        # Saves a local copy and then opens the interactive window
        graph_filename = 'ttfb_graph.png'
        plt.savefig(graph_filename, dpi=300)
        print(f"    => Local copy saved as '{graph_filename}'.")
        # plt.show() # Commented out to prevent attempting to open window on Vultr/SSH
    else:
        print("    => Error: No valid non-new data points found to graph.")

    print("\n==================================================")

analyze_session()