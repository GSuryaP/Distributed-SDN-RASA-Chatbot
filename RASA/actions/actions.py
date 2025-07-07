import requests
from typing import List, Dict, Any
from rasa_sdk import Action, Tracker
from rasa_sdk.executor import CollectingDispatcher
from rasa_sdk.events import SlotSet, EventType
import time

# Configurable ONOS controllers (IPs and ports)
ONOS_CONTROLLERS = [
    {"ip": "localhost", "port": 8181},
    {"ip": "localhost", "port": 8182},
    {"ip": "localhost", "port": 8183},
    {"ip": "localhost", "port": 8184},
    {"ip": "localhost", "port": 8185},
]

AUTH = ("onos", "rocks")


# === Utility: Request with failover and mastership-aware ===
def send_to_healthy_controller(endpoint: str, method="get", data=None, json=None, device_id=None, require_mastership=False) -> Any:
    for ctrl in ONOS_CONTROLLERS:
        try:
            # If checking mastership is required
            if require_mastership and device_id:
                master_url = f"http://{ctrl['ip']}:{ctrl['port']}/onos/v1/mastership/{device_id}"
                master_resp = requests.get(master_url, auth=AUTH, timeout=2)
                if not master_resp.ok:
                    continue
                master_id = master_resp.json().get("master", {}).get("id")
                if master_id and ctrl["ip"] not in master_id:
                    continue

            url = f"http://{ctrl['ip']}:{ctrl['port']}{endpoint}"
            resp = requests.request(method, url, auth=AUTH, timeout=3, data=data, json=json)
            if resp.ok:
                return resp.json() if resp.headers.get("Content-Type", "").startswith("application/json") else resp.text

        except requests.RequestException:
            time.sleep(0.3)
            continue
    return {"error": "All controllers unreachable or not master for this device"}



# === Action: Get Devices ===
class ActionGetDevices(Action):
    def name(self) -> str:
        return "action_get_devices"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[str, Any]) -> List[EventType]:
        result = send_to_healthy_controller("/onos/v1/devices")
        if "error" in result:
            dispatcher.utter_message(text="❌ Could not reach any ONOS controller.")
        else:
            devices = [d["id"] for d in result.get("devices", [])]
            dispatcher.utter_message(text=f"🖧 Devices: {', '.join(devices)}" if devices else "No devices found.")
        return []


# === Action: Add Flow ===
class ActionAddFlow(Action):
    def name(self) -> str:
        return "action_add_flow"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[str, Any]) -> List[EventType]:
        device_id = tracker.get_slot("device_id") or "of:0000000000000001"
        priority = int(tracker.get_slot("priority") or 40000)
        in_port = tracker.get_slot("in_port") or "1"
        out_port = tracker.get_slot("out_port") or "2"

        flow = {
            "priority": priority,
            "timeout": 0,
            "isPermanent": True,
            "deviceId": device_id,
            "treatment": {
                "instructions": [
                    {"type": "OUTPUT", "port": out_port}
                ]
            },
            "selector": {
                "criteria": [
                    {"type": "IN_PORT", "port": in_port}
                ]
            }
        }

        result = send_to_healthy_controller(f"/onos/v1/flows/{device_id}", method="post", json=flow, device_id=device_id, require_mastership=True)
        if "error" in result:
            dispatcher.utter_message(text="❌ Failed to install flow rule.")
        else:
            dispatcher.utter_message(text=f"✅ Flow added on {device_id}.")
        return []


# === Action: Get Controller Status ===
class ActionCheckControllers(Action):
    def name(self) -> str:
        return "action_check_controllers"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[str, Any]) -> List[EventType]:
        reachable = []
        for ctrl in ONOS_CONTROLLERS:
            try:
                url = f"http://{ctrl['ip']}:{ctrl['port']}/onos/v1/cluster/nodes"
                resp = requests.get(url, auth=AUTH, timeout=2)
                if resp.ok:
                    reachable.append(ctrl["ip"])
            except:
                continue
        if reachable:
            dispatcher.utter_message(text=f"✅ Active controllers: {', '.join(reachable)}")
        else:
            dispatcher.utter_message(text="❌ All controllers seem down.")
        return []
        
class ActionDefaultFallback(Action):
    def name(self):
        return "action_default_fallback"

    def run(self, dispatcher, tracker, domain):
        dispatcher.utter_message(text="Sorry, I didn't catch that. Could you rephrase?")
        return []

class ActionGetHosts(Action):
    def name(self) -> str:
        return "action_get_hosts"

    def run(self, dispatcher, tracker, domain):
        result = send_to_healthy_controller("/onos/v1/hosts")
        if "error" in result:
            dispatcher.utter_message(text="❌ Could not fetch hosts.")
        else:
            hosts = [h["id"] for h in result.get("hosts", [])]
            dispatcher.utter_message(text=f"🏠 Hosts: {', '.join(hosts)}" if hosts else "No hosts found.")
        return []

class ActionBlockHost(Action):
    def name(self) -> str:
        return "action_block_host"

    def run(self, dispatcher, tracker, domain):
        host_id = tracker.get_slot("host_id")
        if not host_id:
            dispatcher.utter_message(text="⚠️ Please provide a host ID.")
            return []
        result = send_to_healthy_controller(f"/onos/v1/acl/deny/{host_id}", method="post", device_id=host_id, require_mastership=True)
        if "error" in result:
            dispatcher.utter_message(text="❌ Failed to block the host.")
        else:
            dispatcher.utter_message(text=f"🚫 Host {host_id} blocked.")
        return []

class ActionUnblockHost(Action):
    def name(self) -> str:
        return "action_unblock_host"

    def run(self, dispatcher, tracker, domain):
        host_id = tracker.get_slot("host_id")
        if not host_id:
            dispatcher.utter_message(text="⚠️ Please provide a host ID.")
            return []
        result = send_to_healthy_controller(f"/onos/v1/acl/allow/{host_id}", method="post", device_id=host_id, require_mastership=True)
        if "error" in result:
            dispatcher.utter_message(text="❌ Failed to unblock the host.")
        else:
            dispatcher.utter_message(text=f"✅ Host {host_id} unblocked.")
        return []

class ActionGetPorts(Action):
    def name(self) -> str:
        return "action_get_ports"

    def run(self, dispatcher, tracker, domain):
        device_id = tracker.get_slot("device_id")
        if not device_id:
            dispatcher.utter_message(text="⚠️ Please provide the device ID.")
            return []
        result = send_to_healthy_controller(f"/onos/v1/devices/{device_id}/ports")
        if "error" in result:
            dispatcher.utter_message(text="❌ Failed to fetch ports.")
        else:
            ports = [str(p["port"]) for p in result.get("ports", [])]
            dispatcher.utter_message(text=f"🔌 Ports on {device_id}: {', '.join(ports)}")
        return []

class ActionGetFlows(Action):
    def name(self) -> str:
        return "action_get_flows"

    def run(self, dispatcher, tracker, domain):
        device_id = tracker.get_slot("device_id")
        if not device_id:
            dispatcher.utter_message(text="⚠️ Please provide the device ID.")
            return []
        result = send_to_healthy_controller(f"/onos/v1/flows/{device_id}")
        if "error" in result:
            dispatcher.utter_message(text="❌ Failed to fetch flows.")
        else:
            flows = result.get("flows", [])
            flow_strs = [f"{f['id']} (pri: {f['priority']})" for f in flows]
            dispatcher.utter_message(text=f"🔁 Flows on {device_id}: {', '.join(flow_strs)}" if flow_strs else "No flows found.")
        return []

class ActionShowTopology(Action):
    def name(self) -> str:
        return "action_show_topology"

    def run(self, dispatcher, tracker, domain):
        result = send_to_healthy_controller("/onos/v1/topology")
        if "error" in result:
            dispatcher.utter_message(text="❌ Failed to fetch topology.")
        else:
            summary = result.get("topology", {})
            msg = (
                f"🌐 Topology:\n"
                f"Devices: {summary.get('devices', 0)}, "
                f"Links: {summary.get('links', 0)}, "
                f"Hosts: {summary.get('hosts', 0)}"
            )
            dispatcher.utter_message(text=msg)
        return []
