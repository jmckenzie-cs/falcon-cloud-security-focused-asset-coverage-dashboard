import React, { useContext, useEffect, useState } from "react";
import { FalconApiContext } from "../contexts/falcon-api-context";

function formatCount(count, estimated) {
  const formatted = count.toLocaleString();
  return estimated ? `${formatted}*` : formatted;
}

function formatCoverage(rate, estimated) {
  const formatted = `${rate}%`;
  return estimated ? `${formatted}*` : formatted;
}

function fmtOrDash(val, fmt, est) {
  return val === null || val === undefined ? "—" : fmt(val, est);
}

function CoverageTable({ data }) {
  const total_assets = data?.total_assets ?? 0;
  const rows = data?.rows ?? [];

  return (
    <div style={{ fontFamily: "sans-serif", padding: "24px" }}>
      <p style={{ fontWeight: "bold", marginBottom: "8px", fontSize: "15px" }}>
        <span>{total_assets.toLocaleString()} total assets</span>{" "}
        <span style={{ fontWeight: "normal" }}>across sensor-capable types:</span>
      </p>

      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "14px" }}>
        <thead>
          <tr style={{ borderBottom: "1px solid #ccc" }}>
            {["Asset Type", "Total Count", "With Sensors", "Without Sensors", "Coverage Rate"].map(
              (col) => (
                <th
                  key={col}
                  style={{
                    textAlign: "left",
                    padding: "6px 16px 6px 0",
                    fontWeight: "normal",
                    color: "#555",
                  }}
                >
                  {col}
                </th>
              )
            )}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
          <tr>
            <td colSpan={5} style={{ padding: "24px 0", color: "var(--token-color-text-secondary, #aaa)", fontSize: "13px" }}>
              No assets found. Check that cloud accounts are registered in Falcon Cloud Security.
            </td>
          </tr>
        )}
        {rows.map((row) => (
          <>
            <tr key={row.name} style={{ borderBottom: "1px solid #eee" }}>
              <td style={{ padding: "14px 16px 14px 0", fontWeight: "bold", color: "#1a6fd4" }}>
                {row.name}
              </td>
              <td style={{ padding: "14px 16px 14px 0" }}>
                {fmtOrDash(row.total_count, formatCount, row.estimated)}
              </td>
              <td style={{ padding: "14px 16px 14px 0" }}>
                {fmtOrDash(row.with_sensors, formatCount, row.estimated)}
              </td>
              <td style={{ padding: "14px 16px 14px 0" }}>
                {fmtOrDash(row.without_sensors, formatCount, row.estimated)}
              </td>
              <td style={{ padding: "14px 16px 14px 0" }}>
                {fmtOrDash(row.coverage_rate, formatCoverage, row.estimated)}
              </td>
            </tr>
            {row.errors && row.errors.length > 0 && (
              <tr key={`${row.name}-err`}>
                <td colSpan={5} style={{ padding: "4px 0 12px", fontSize: "11px", color: "#e57373" }}>
                  API error: {JSON.stringify(row.errors)}
                </td>
              </tr>
            )}
          </>
        ))}
        </tbody>
      </table>

      {rows.some((r) => r.estimated) && (
        <p style={{ marginTop: "12px", fontSize: "12px", color: "#888" }}>
          * Count exceeds one page of API results and may be estimated.
        </p>
      )}
      {rows.some((r) => r.name === "K8s Clusters AWS" || r.name === "K8s Clusters Azure") && (
        <p style={{ marginTop: "8px", fontSize: "12px", color: "#888" }}>
          † K8s AWS/Azure sensor coverage counts clusters with ≥1 sensor-equipped worker node,
          limited to clusters with KAC registered. Clusters without KAC are counted as unprotected.
        </p>
      )}
    </div>
  );
}

function UnprotectedSection({ rows, typeDetails, onExpand }) {
  const [expanded, setExpanded] = useState({});

  const detailRows = (rows ?? []).filter(r => r.name !== "K8s Clusters with KAC");
  if (!detailRows.length) return null;

  function toggle(name) {
    const next = !expanded[name];
    setExpanded(e => ({ ...e, [name]: next }));
    if (next && !typeDetails[name]) onExpand(name);
  }

  return (
    <div style={{ padding: "0 24px 24px" }}>
      <p style={{ fontWeight: "bold", fontSize: "14px", marginBottom: "8px" }}>
        Unprotected Assets
      </p>
      {detailRows.map(row => {
        const td = typeDetails[row.name];
        const isExpanded = !!expanded[row.name];
        return (
          <div key={row.name} style={{ marginBottom: "8px" }}>
            <button
              onClick={() => toggle(row.name)}
              style={{ background: "none", border: "none", cursor: "pointer",
                       fontSize: "13px", fontWeight: "bold", color: "#1a6fd4", padding: "4px 0" }}
            >
              {isExpanded ? "▾" : "▸"}{" "}
              {row.name} — {(row.without_sensors ?? 0).toLocaleString()} unprotected
            </button>
            {isExpanded && !td && (
              <p style={{ fontSize: "12px", color: "#aaa", marginLeft: "16px" }}>Loading…</p>
            )}
            {isExpanded && td?.loading && (
              <p style={{ fontSize: "12px", color: "#aaa", marginLeft: "16px" }}>Loading…</p>
            )}
            {isExpanded && td?.error && (
              <p style={{ fontSize: "12px", color: "#e57373", marginLeft: "16px" }}>Failed to load — try collapsing and re-expanding.</p>
            )}
            {isExpanded && td && !td.loading && !td.error && td.assets?.length > 0 && (
              <>
                {td.total > td.shown && (
                  <p style={{ fontSize: "12px", color: "#aaa", marginLeft: "16px", marginBottom: "4px" }}>
                    Showing first {td.shown.toLocaleString()} of {td.total.toLocaleString()}
                  </p>
                )}
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px", marginTop: "4px" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid #ddd" }}>
                      {["Resource ID", "Name", "Account", "Region", "Status"].map(h => (
                        <th key={h} style={{ textAlign: "left", padding: "4px 12px 4px 0",
                                            fontWeight: "normal", color: "#777" }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {td.assets.map((a, i) => (
                      <tr key={i} style={{ borderBottom: "1px solid #f0f0f0" }}>
                        <td style={{ padding: "4px 12px 4px 0", fontFamily: "monospace" }}>{a.resource_id ?? "—"}</td>
                        <td style={{ padding: "4px 12px 4px 0" }}>{a.resource_name ?? "—"}</td>
                        <td style={{ padding: "4px 12px 4px 0" }}>{a.account_id ?? "—"}</td>
                        <td style={{ padding: "4px 12px 4px 0" }}>{a.region ?? "—"}</td>
                        <td style={{ padding: "4px 12px 4px 0" }}>{a.status ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
            {isExpanded && td && !td.loading && !td.error && td.assets?.length === 0 && (
              <p style={{ fontSize: "12px", color: "#aaa", marginLeft: "16px" }}>No unprotected assets.</p>
            )}
          </div>
        );
      })}
    </div>
  );
}

function Home() {
  const { falcon } = useContext(FalconApiContext);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [debugData, setDebugData] = useState(null);
  const [debugLoading, setDebugLoading] = useState(false);
  const [typeDetails, setTypeDetails] = useState({});

  useEffect(() => {
    async function fetchCoverage() {
      try {
        const timeout = new Promise((_, reject) =>
          setTimeout(() => reject(new Error("Request timed out after 30s")), 30000)
        );
        const raw = await Promise.race([
          falcon.cloudFunction({ name: "asset-coverage", version: 1 })
            .execute({ method: "GET", path: "/coverage" }),
          timeout,
        ]);
        console.log("[asset-coverage] raw response:", JSON.stringify(raw));
        const body = raw?.body ?? raw;
        console.log("[asset-coverage] body:", JSON.stringify(body));
        setData(body);
      } catch (err) {
        setError(err?.message || "Failed to load coverage data");
      } finally {
        setLoading(false);
      }
    }
    fetchCoverage();
  }, [falcon]);

  async function fetchTypeDetails(typeName) {
    setTypeDetails(prev => ({ ...prev, [typeName]: { loading: true } }));
    try {
      const raw = await Promise.race([
        falcon.cloudFunction({ name: "asset-coverage", version: 1 })
          .execute({ method: "GET", path: "/details", params: { query: { type: [typeName] } } }),
        new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 60000)),
      ]);
      const group = ((raw?.body ?? raw)?.details ?? [])[0] ?? {};
      setTypeDetails(prev => ({
        ...prev,
        [typeName]: { loading: false, assets: group.assets ?? [], total: group.total ?? 0, shown: group.shown ?? 0 }
      }));
    } catch (err) {
      setTypeDetails(prev => ({ ...prev, [typeName]: { loading: false, error: true } }));
    }
  }

  async function runDebug() {
    setDebugLoading(true);
    setDebugData(null);
    try {
      const raw = await falcon.cloudFunction({ name: "asset-coverage", version: 1 })
        .execute({ method: "GET", path: "/debug" });
      const body = raw?.body ?? raw;
      console.log("[asset-coverage] debug:", JSON.stringify(body));
      setDebugData(body);
    } catch (err) {
      setDebugData({ error: err?.message });
    } finally {
      setDebugLoading(false);
    }
  }

  if (loading) {
    return <div style={{ padding: "24px", color: "var(--token-color-text-secondary, #aaa)" }}>Loading coverage data…</div>;
  }

  if (error) {
    return <div style={{ padding: "24px", color: "var(--token-color-text-danger, #ef5350)" }}>Error: {error}</div>;
  }

  if (!data) {
    return <div style={{ padding: "24px", color: "var(--token-color-text-secondary, #aaa)" }}>No data returned — check browser console for details.</div>;
  }

  return (
    <div>
      <CoverageTable data={data} />
      {data && <UnprotectedSection rows={data.rows} typeDetails={typeDetails} onExpand={fetchTypeDetails} />}
      <div style={{ padding: "0 24px 24px" }}>
        <button
          onClick={runDebug}
          disabled={debugLoading}
          style={{ fontSize: "12px", padding: "4px 10px", cursor: "pointer" }}
        >
          {debugLoading ? "Running debug…" : "Run API Debug"}
        </button>
        {debugData && (
          <pre style={{ marginTop: "12px", fontSize: "11px", background: "var(--token-color-background-body-secondary, #1e1e1e)", color: "var(--token-color-text-primary, #ccc)", padding: "12px", borderRadius: "4px", overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
            {JSON.stringify(debugData, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}

export { Home };
