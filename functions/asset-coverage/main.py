import json

from crowdstrike.foundry.function import Function, Request, Response
from falconpy import CloudSecurityAssets, Hosts, KubernetesProtection

func = Function.instance()

# Asset types using managed_by:'Sensor' FQL for sensor detection (v2)
ASSET_TYPES = [
    {
        "name": "AWS EC2",
        "fql": "resource_type:'AWS::EC2::Instance'+active:true",
    },
    {
        "name": "AWS ECS Tasks",
        "fql": "resource_type:'AWS::ECS::Task'+active:true",
    },
    {
        "name": "Azure Virtual Machines",
        "fql": "cloud_provider:'azure'+resource_type:'Microsoft.Compute/virtualMachines'+active:true",
    },
    {
        "name": "GCP Compute Instances",
        "fql": "cloud_provider:'gcp'+resource_type:'compute.googleapis.com/Instance'+active:true",
    },
    {
        "name": "K8s Clusters AWS",
        "fql": "cloud_provider:'aws'+resource_type:'AWS::EKS::Cluster'+active:true",
        "k8s_cloud": "aws",
    },
    {
        "name": "K8s Clusters Azure",
        "fql": "cloud_provider:'azure'+resource_type:'Microsoft.ContainerService/managedClusters'+active:true",
        "k8s_cloud": "azure",
    },
    {
        "name": "K8s Clusters GCP",
        "fql": "cloud_provider:'gcp'+resource_type:'container.googleapis.com/Cluster'+active:true",
        "k8s_cloud": "gcp",
    },
]

SENSOR_FQL = "+managed_by:'Sensor'"

# Maps KAC host service_provider values to k8s_cloud keys.
# UNKNOWN (null service_provider) confirmed as Azure ARO via hostname pattern
# (dmord013kbfce8ed25.westeurope.aroapp.io) from debug probe.
SP_TO_CLOUD = {
    "AWS_EC2_V2": "aws",
    "AZURE": "azure",
    "GCP": "gcp",
    "": "azure",  # null service_provider → Azure ARO clusters
}

# Falcon sensor indicators for ECS task definition configuration inspection
FALCON_IMAGE_HINTS = ["falcon-container", "falcon-sensor", "falconutil"]
FALCON_ENV_VARS = {"CS_FARGATE_MODE", "FALCONCTL_OPT", "CrowdStrike_CID", "CrowdStrike_CCid"}
FALCON_VOLUMES = {"/tmp/CrowdStrike"}


def get_pagination_total(resp: dict) -> int:
    return (
        (resp.get("body") or {})
        .get("meta", {})
        .get("pagination", {})
        .get("total", 0)
    )


def is_falcon_patched(configuration_raw: str) -> bool:
    """Inspect task definition configuration JSON for Falcon sensor indicators."""
    if not configuration_raw:
        return False
    try:
        config = json.loads(configuration_raw)
    except (json.JSONDecodeError, TypeError):
        return False

    for container in config.get("containerDefinitions") or []:
        image = (container.get("image") or "").lower()
        name = (container.get("name") or "").lower()

        if any(hint in image for hint in FALCON_IMAGE_HINTS):
            return True
        if any(hint in name for hint in ["falcon", "crowdstrike"]):
            return True

        env_vars = {e.get("name") for e in (container.get("environment") or [])}
        if env_vars & FALCON_ENV_VARS:
            return True

        mounts = [m.get("containerPath", "") for m in (container.get("mountPoints") or [])]
        if any(any(fv in m for fv in FALCON_VOLUMES) for m in mounts):
            return True

    return False


def get_all_ids(falcon: CloudSecurityAssets, fql: str) -> list:
    """Paginate through all asset IDs matching an FQL filter."""
    ids = []
    offset = 0
    while True:
        resp = falcon.query_assets(filter=fql, limit=500, offset=offset)
        if resp["status_code"] != 200:
            break
        body = resp.get("body") or {}
        batch = body.get("resources") or []
        ids.extend(batch)
        total = body.get("meta", {}).get("pagination", {}).get("total", 0)
        offset += len(batch)
        if offset >= total or not batch:
            break
    return ids


def get_ecs_task_def_counts(falcon: CloudSecurityAssets) -> dict:
    """Count patched/unpatched ECS task definitions by inspecting container config."""
    ids = get_all_ids(falcon, "resource_type:'AWS::ECS::TaskDefinition'")
    total_count = len(ids)

    if not total_count:
        return {
            "name": "AWS ECS Task Definitions",
            "total_count": 0,
            "with_sensors": 0,
            "without_sensors": 0,
            "coverage_rate": 0.0,
            "estimated": False,
            "errors": [],
        }

    patched = 0
    api_errors = []
    for i in range(0, len(ids), 100):
        resp = falcon.get_assets(ids=ids[i:i + 100])
        if resp["status_code"] != 200:
            api_errors.append({
                "op": "get_assets_batch",
                "status": resp["status_code"],
                "errors": (resp.get("body") or {}).get("errors"),
            })
            continue
        for r in (resp.get("body") or {}).get("resources") or []:
            if is_falcon_patched(r.get("configuration", "")):
                patched += 1

    without = total_count - patched
    coverage = round(patched / total_count * 100, 1) if total_count > 0 else 0.0

    return {
        "name": "AWS ECS Task Definitions",
        "total_count": total_count,
        "with_sensors": patched,
        "without_sensors": without,
        "coverage_rate": coverage,
        "estimated": False,
        "errors": api_errors,
    }


def get_asset_counts(falcon: CloudSecurityAssets, asset_type: dict) -> dict:
    """Two fast queries: total count + with-sensor count via managed_by:'Sensor'."""
    fql = asset_type["fql"]
    api_errors = []

    resp_total = falcon.query_assets(filter=fql, limit=1)
    if resp_total["status_code"] != 200:
        api_errors.append({
            "op": "query_assets_total",
            "status": resp_total["status_code"],
            "errors": (resp_total.get("body") or {}).get("errors"),
        })
        return {
            "name": asset_type["name"],
            "total_count": 0,
            "with_sensors": 0,
            "without_sensors": 0,
            "coverage_rate": 0.0,
            "estimated": False,
            "errors": api_errors,
        }

    total_count = get_pagination_total(resp_total)

    resp_sensor = falcon.query_assets(filter=fql + SENSOR_FQL, limit=1)
    if resp_sensor["status_code"] != 200:
        api_errors.append({
            "op": "query_assets_sensor",
            "status": resp_sensor["status_code"],
            "errors": (resp_sensor.get("body") or {}).get("errors"),
        })
        with_sensors = 0
    else:
        with_sensors = get_pagination_total(resp_sensor)

    without_sensors = total_count - with_sensors
    coverage = round(with_sensors / total_count * 100, 1) if total_count > 0 else 0.0

    return {
        "name": asset_type["name"],
        "total_count": total_count,
        "with_sensors": with_sensors,
        "without_sensors": without_sensors,
        "coverage_rate": coverage,
        "estimated": False,
        "errors": api_errors,
    }


def get_k8s_cluster_sensor_counts() -> dict:
    """For each KAC-registered cluster, check if it has ≥1 sensor-equipped worker node.

    Returns {cloud_key: count_of_clusters_with_sensor_nodes}.
    Only clusters with KAC can be probed (we need their k8s_cluster_id UUID).
    Clusters without KAC are conservatively counted as without sensors.
    """
    hosts = Hosts()
    resp = hosts.query_devices_by_filter(
        filter="product_type_desc:'Kubernetes Cluster'", limit=100
    )
    if resp["status_code"] != 200:
        return {"aws": 0, "azure": 0, "gcp": 0}

    kac_ids = ((resp.get("body") or {}).get("resources") or [])
    if not kac_ids:
        return {"aws": 0, "azure": 0, "gcp": 0}

    det = hosts.get_device_details(ids=kac_ids)
    kac_resources = ((det.get("body") or {}).get("resources") or [])

    counts = {"aws": 0, "azure": 0, "gcp": 0}
    for kac_host in kac_resources:
        sp = kac_host.get("service_provider") or ""
        cloud = SP_TO_CLOUD.get(sp)
        if not cloud:
            continue
        cluster_uuid = kac_host.get("k8s_cluster_id")
        if not cluster_uuid:
            continue
        r = hosts.query_devices_by_filter(
            filter=f"k8s_cluster_id:'{cluster_uuid}'", limit=1
        )
        if r["status_code"] == 200 and get_pagination_total(r) > 0:
            counts[cloud] += 1  # this cluster has ≥1 sensor-equipped worker node
    return counts


def get_k8s_cluster_row(falcon: CloudSecurityAssets, asset_type: dict, with_sensors: int) -> dict:
    """Build a K8s cluster row using CloudSecurityAssets for total and pre-computed sensor count."""
    resp_total = falcon.query_assets(filter=asset_type["fql"], limit=1)
    errors = []
    if resp_total["status_code"] != 200:
        errors.append({
            "op": "query_assets_total",
            "status": resp_total["status_code"],
            "errors": (resp_total.get("body") or {}).get("errors"),
        })
        total = 0
    else:
        total = get_pagination_total(resp_total)

    # CSA has no records for this cloud but KAC found clusters — use KAC count as total
    if total == 0 and with_sensors > 0:
        total = with_sensors

    without = max(0, total - with_sensors)
    coverage = round(with_sensors / total * 100, 1) if total > 0 else 0.0
    return {
        "name": asset_type["name"],
        "total_count": total,
        "with_sensors": min(with_sensors, total),
        "without_sensors": without,
        "coverage_rate": coverage,
        "estimated": False,
        "errors": errors,
    }


def get_k8s_kac_counts(falcon: CloudSecurityAssets) -> dict:
    """Count K8s clusters with KAC deployed.

    Total: sum of clusters from CloudSecurityAssets across all clouds.
           For clouds where CSA returns 0 but KAC found clusters, KAC count is used as fallback.
    KAC:   count of hosts registered with product_type_desc:'Kubernetes Cluster'
           (each KAC deployment registers one such host per cluster).
    """
    errors = []

    # Total cluster count from CloudSecurityAssets, per cloud key
    csa_totals = {}  # k8s_cloud → count
    for asset_type in ASSET_TYPES:
        cloud_key = asset_type.get("k8s_cloud")
        if not cloud_key:
            continue
        resp = falcon.query_assets(filter=asset_type["fql"], limit=1)
        if resp["status_code"] == 200:
            csa_totals[cloud_key] = get_pagination_total(resp)
        else:
            csa_totals[cloud_key] = 0
            errors.append({
                "op": "k8s_total",
                "filter": asset_type["fql"],
                "status": resp["status_code"],
                "errors": (resp.get("body") or {}).get("errors"),
            })

    # KAC count from Hosts API (devices:read scope)
    hosts = Hosts()
    resp_kac = hosts.query_devices_by_filter(
        filter="product_type_desc:'Kubernetes Cluster'", limit=1
    )
    if resp_kac["status_code"] == 200:
        kac_count = (
            (resp_kac.get("body") or {})
            .get("meta", {})
            .get("pagination", {})
            .get("total", 0)
        )
    else:
        kac_count = 0
        if sum(csa_totals.values()) > 0:
            errors.append({
                "op": "kac_hosts_query",
                "status": resp_kac["status_code"],
                "errors": (resp_kac.get("body") or {}).get("errors"),
            })

    # For clouds where CSA has no records, use per-cloud KAC count as fallback total.
    # Get per-cloud KAC counts from Hosts details.
    csa_missing_clouds = {k for k, v in csa_totals.items() if v == 0}
    if csa_missing_clouds and kac_count > 0:
        resp_ids = hosts.query_devices_by_filter(
            filter="product_type_desc:'Kubernetes Cluster'", limit=100
        )
        kac_ids = ((resp_ids.get("body") or {}).get("resources") or [])
        if kac_ids:
            det = hosts.get_device_details(ids=kac_ids)
            from collections import Counter
            sp_cloud_counts = Counter()
            for h in ((det.get("body") or {}).get("resources") or []):
                sp = h.get("service_provider") or ""
                cloud = SP_TO_CLOUD.get(sp)
                if cloud in csa_missing_clouds:
                    sp_cloud_counts[cloud] += 1
            for cloud, count in sp_cloud_counts.items():
                csa_totals[cloud] = count

    total = sum(csa_totals.values())

    return {
        "name": "K8s Clusters with KAC",
        "total_count": total,
        "with_sensors": kac_count,
        "without_sensors": max(0, total - kac_count),
        "coverage_rate": round(kac_count / total * 100, 1) if total > 0 else 0.0,
        "estimated": False,
        "errors": errors,
    }


def get_without_sensor_assets(falcon: CloudSecurityAssets, fql: str, cap: int = 500) -> dict:
    """Return up to cap assets without sensors, plus the true total count."""
    all_ids = get_all_ids(falcon, fql)
    sensor_ids = set(get_all_ids(falcon, fql + SENSOR_FQL))
    without_ids = [i for i in all_ids if i not in sensor_ids]

    total = len(without_ids)
    fetch_ids = without_ids[:cap]
    assets = []
    for i in range(0, len(fetch_ids), 100):
        resp = falcon.get_assets(ids=fetch_ids[i:i + 100])
        for r in (resp.get("body") or {}).get("resources") or []:
            assets.append({
                "resource_id":   r.get("resource_id"),
                "resource_name": r.get("resource_name"),
                "account_id":    r.get("account_id"),
                "region":        r.get("region"),
                "status":        r.get("status"),
            })
    return {"assets": assets, "total": total, "shown": len(assets)}


def get_unpatched_task_def_assets(falcon: CloudSecurityAssets, cap: int = 500) -> dict:
    """Return identifying fields for unpatched ECS task definitions."""
    ids = get_all_ids(falcon, "resource_type:'AWS::ECS::TaskDefinition'")
    unpatched = []
    for i in range(0, len(ids), 100):
        resp = falcon.get_assets(ids=ids[i:i + 100])
        for r in (resp.get("body") or {}).get("resources") or []:
            if not is_falcon_patched(r.get("configuration", "")):
                unpatched.append({
                    "resource_id":   r.get("resource_id"),
                    "resource_name": r.get("resource_name"),
                    "account_id":    r.get("account_id"),
                    "region":        r.get("region"),
                    "status":        None,
                })
    total = len(unpatched)
    return {"assets": unpatched[:cap], "total": total, "shown": min(total, cap)}


def get_k8s_cluster_assets(falcon: CloudSecurityAssets, fql: str, k8s_cloud: str) -> dict:
    """Return CSA cluster entities that do NOT have KAC, using name-based correlation."""
    ids = get_all_ids(falcon, fql)
    all_assets = []
    for i in range(0, len(ids), 100):
        resp = falcon.get_assets(ids=ids[i:i + 100])
        for r in (resp.get("body") or {}).get("resources") or []:
            all_assets.append({
                "resource_id":   r.get("resource_id"),
                "resource_name": r.get("resource_name"),
                "account_id":    r.get("account_id"),
                "region":        r.get("region"),
                "status":        None,
            })

    # Build set of cluster names that have KAC for this cloud, using SP_TO_CLOUD mapping
    hosts = Hosts()
    resp_h = hosts.query_devices_by_filter(
        filter="product_type_desc:'Kubernetes Cluster'", limit=100
    )
    kac_names = set()
    if resp_h["status_code"] == 200:
        kac_ids = (resp_h.get("body") or {}).get("resources") or []
        if kac_ids:
            det = hosts.get_device_details(ids=kac_ids)
            for h in (det.get("body") or {}).get("resources") or []:
                sp = h.get("service_provider") or ""
                if SP_TO_CLOUD.get(sp) != k8s_cloud:
                    continue
                hn = h.get("hostname") or ""
                # Azure ARM paths end in /managedClusters/CLUSTERNAME — extract last segment
                name = hn.split("/")[-1].lower() if "/" in hn else hn.lower()
                kac_names.add(name)

    unprotected = [
        a for a in all_assets
        if (a.get("resource_name") or "").lower() not in kac_names
    ]
    total = len(unprotected)
    return {"assets": unprotected, "total": total, "shown": total}


@func.handler(method="GET", path="/details")
def on_details(request: Request) -> Response:
    falcon = CloudSecurityAssets()
    type_name = (request.params.query or {}).get("type", [""])[0]

    type_map = {at["name"]: at for at in ASSET_TYPES}

    if type_name == "AWS ECS Task Definitions":
        detail = get_unpatched_task_def_assets(falcon)
        return Response(body={"details": [{"name": type_name, **detail}]}, code=200)

    if type_name in type_map:
        asset_type = type_map[type_name]
        k8s_cloud = asset_type.get("k8s_cloud")
        if k8s_cloud:
            detail = get_k8s_cluster_assets(falcon, asset_type["fql"], k8s_cloud)
        else:
            detail = get_without_sensor_assets(falcon, asset_type["fql"])
        return Response(body={"details": [{"name": type_name, **detail}]}, code=200)

    return Response(body={"error": f"unknown type: {type_name}"}, code=400)


@func.handler(method="GET", path="/coverage")
def on_get(request: Request) -> Response:
    falcon = CloudSecurityAssets()

    # Pre-fetch K8s cluster sensor counts once (one Hosts API round-trip per KAC cluster)
    k8s_sensor_counts = get_k8s_cluster_sensor_counts()

    rows = []
    total_assets = 0

    for asset_type in ASSET_TYPES:
        cloud_key = asset_type.get("k8s_cloud")
        if cloud_key:
            row = get_k8s_cluster_row(falcon, asset_type, k8s_sensor_counts.get(cloud_key, 0))
        else:
            row = get_asset_counts(falcon, asset_type)
        rows.append(row)
        total_assets += row["total_count"]

    # ECS Task Definitions: inspect container config for Falcon sensor
    ecs_row = get_ecs_task_def_counts(falcon)
    rows.insert(2, ecs_row)  # keep original table order after ECS Tasks
    total_assets += ecs_row["total_count"]

    kac_row = get_k8s_kac_counts(falcon)
    rows.append(kac_row)
    # NOTE: do NOT add kac_row["total_count"] to total_assets — those clusters are
    # already counted in K8s Clusters AWS and K8s Clusters Azure rows above.

    return Response(
        body={"total_assets": total_assets, "rows": rows},
        code=200,
    )


@func.handler(method="GET", path="/debug")
def on_debug(request: Request) -> Response:
    import traceback as tb
    result = {}

    # Test 1: KubernetesProtection scope
    try:
        kube = KubernetesProtection()
        resp_kp = kube.read_clusters_combined(limit=1)
        body_kp = resp_kp.get("body") or {}
        resources = body_kp.get("resources") or []
        result["kp_status"] = resp_kp["status_code"]
        result["kp_errors"] = body_kp.get("errors")
        result["kp_total"] = body_kp.get("meta", {}).get("pagination", {}).get("total", 0)
        result["kp_sample_agent_coverage"] = (
            resources[0].get("agent_coverage") if resources else None
        )
    except Exception as exc:
        result["kp_exception"] = str(exc)
        result["kp_traceback"] = tb.format_exc()

    # Test 2: Hosts API (existing KAC workaround)
    try:
        hosts = Hosts()
        resp_h = hosts.query_devices_by_filter(
            filter="product_type_desc:'Kubernetes Cluster'", limit=1
        )
        result["hosts_status"] = resp_h["status_code"]
        result["hosts_errors"] = (resp_h.get("body") or {}).get("errors")
        result["hosts_kac_total"] = (
            (resp_h.get("body") or {})
            .get("meta", {}).get("pagination", {}).get("total", 0)
        )
    except Exception as exc:
        result["hosts_exception"] = str(exc)

    # Test 3: KAC service_provider distribution — fetch all 13 KAC hosts
    try:
        hosts = Hosts()

        # Get all KAC host IDs
        resp_kac_ids = hosts.query_devices_by_filter(
            filter="product_type_desc:'Kubernetes Cluster'", limit=100
        )
        kac_ids = ((resp_kac_ids.get("body") or {}).get("resources") or [])
        result["kac_total_ids"] = len(kac_ids)

        if kac_ids:
            # Fetch details for all KAC hosts
            det = hosts.get_device_details(ids=kac_ids)
            resources = ((det.get("body") or {}).get("resources") or [])
            # Build service_provider distribution
            from collections import Counter
            sp_counts = Counter(r.get("service_provider", "UNKNOWN") for r in resources)
            result["kac_service_provider_distribution"] = dict(sp_counts)
            # Show first sample per unique service_provider
            seen = set()
            samples = []
            for r in resources:
                sp = r.get("service_provider", "UNKNOWN")
                if sp not in seen:
                    seen.add(sp)
                    samples.append({k: r.get(k) for k in
                        ["service_provider", "cloud_provider", "hostname", "product_type_desc"]})
            result["kac_samples_per_provider"] = samples

        # Probe counts by service_provider for KAC hosts
        for sp in ["AZURE", "AWS_EKS", "AWS", "AWS_EC2_V2", "GCP"]:
            r = hosts.query_devices_by_filter(
                filter=f"product_type_desc:'Kubernetes Cluster'+service_provider:'{sp}'", limit=1
            )
            result[f"kac_sp_{sp}"] = get_pagination_total(r) if r["status_code"] == 200 else f"error:{r['status_code']}"

        # Inspect all UNKNOWN (null service_provider) KAC hosts in detail
        resp_unk = hosts.query_devices_by_filter(
            filter="product_type_desc:'Kubernetes Cluster'", limit=100
        )
        all_ids = ((resp_unk.get("body") or {}).get("resources") or [])
        if all_ids:
            det_all = hosts.get_device_details(ids=all_ids)
            all_resources = ((det_all.get("body") or {}).get("resources") or [])
            unknown_hosts = [r for r in all_resources if not r.get("service_provider")]
            result["kac_unknown_count"] = len(unknown_hosts)
            result["kac_unknown_details"] = [
                {k: r.get(k) for k in ["service_provider", "cloud_provider", "hostname",
                                        "external_ip", "local_ip", "os_version", "tags"]}
                for r in unknown_hosts
            ]

    except Exception as exc:
        result["kac_probe_exception"] = str(exc)
        result["kac_probe_traceback"] = tb.format_exc()

    # Test 4: Specific k8s_cluster_id UUID query on Hosts API
    try:
        hosts = Hosts()
        known_uuid = "a4b18f90-33d7-4b2e-8a90-f7094f232da6"  # from KAC sample (AZURE cluster)
        r = hosts.query_devices_by_filter(filter=f"k8s_cluster_id:'{known_uuid}'", limit=5)
        result["k8s_uuid_query_status"] = r["status_code"]
        result["k8s_uuid_query_count"] = get_pagination_total(r) if r["status_code"] == 200 else None
        result["k8s_uuid_query_error"] = (r.get("body") or {}).get("errors") if r["status_code"] != 200 else None
        if r["status_code"] == 200:
            sample_ids = ((r.get("body") or {}).get("resources") or [])
            if sample_ids:
                det = hosts.get_device_details(ids=sample_ids[:1])
                sample = ((det.get("body") or {}).get("resources") or [{}])[0]
                result["k8s_node_sample"] = {k: sample.get(k) for k in
                    ["k8s_cluster_id", "service_provider", "hostname", "product_type_desc", "platform_name"]}
    except Exception as exc:
        result["k8s_uuid_probe_exception"] = str(exc)
        result["k8s_uuid_probe_traceback"] = tb.format_exc()

    # Test 5: GCP GKE resource type discovery
    try:
        csa = CloudSecurityAssets()
        # Probe candidate resource types for GCP GKE clusters
        gcp_candidates = [
            "container.googleapis.com/Cluster",
            "container.googleapis.com/cluster",
            "gke.googleapis.com/Cluster",
            "k8s.io/Cluster",
        ]
        result["gcp_k8s_type_probes"] = {}
        for rt in gcp_candidates:
            r = csa.query_assets(filter=f"cloud_provider:'gcp'+resource_type:'{rt}'+active:true", limit=1)
            result["gcp_k8s_type_probes"][rt] = (
                get_pagination_total(r) if r["status_code"] == 200
                else f"error:{r['status_code']}"
            )
        # Also sample all active GCP resource types (limit 500, pull resource_type from entities)
        ids_resp = csa.query_assets(filter="cloud_provider:'gcp'+active:true", limit=500)
        gcp_ids = ((ids_resp.get("body") or {}).get("resources") or [])
        if gcp_ids:
            det_resp = csa.get_assets(ids=gcp_ids[:10])
            sample_types = list({
                r.get("resource_type") for r in
                ((det_resp.get("body") or {}).get("resources") or [])
                if r.get("resource_type")
            })
            result["gcp_sample_resource_types"] = sample_types
            result["gcp_total_active"] = get_pagination_total(ids_resp)
    except Exception as exc:
        result["gcp_k8s_probe_exception"] = str(exc)

    return Response(body=result, code=200)


if __name__ == "__main__":
    func.run()
