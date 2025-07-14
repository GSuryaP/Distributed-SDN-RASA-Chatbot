import requests
from typing import Any, Text, Dict, List
from rasa_sdk import Action, Tracker
from rasa_sdk.executor import CollectingDispatcher
from rasa_sdk.events import SlotSet, EventType
import time
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    """
    Send request to a healthy ONOS controller with failover support.
    
    Args:
        endpoint: API endpoint to call
        method: HTTP method (get, post, put, delete)
        data: Request data for non-JSON payloads
        json: JSON payload for requests
        device_id: Device ID for mastership checks
        require_mastership: Whether to check mastership before sending request
    
    Returns:
        Response data or error dictionary
    """
    for ctrl in ONOS_CONTROLLERS:
        try:
            # If checking mastership is required
            if require_mastership and device_id:
                master_url = f"http://{ctrl['ip']}:{ctrl['port']}/onos/v1/mastership/{device_id}"
                try:
                    master_resp = requests.get(master_url, auth=AUTH, timeout=2)
                    if master_resp.ok:
                        master_data = master_resp.json()
                        master_id = master_data.get("master", {}).get("id", "")
                        # Check if this controller is the master
                        if master_id and f"{ctrl['ip']}:{ctrl['port']}" not in master_id:
                            logger.info(f"Controller {ctrl['ip']}:{ctrl['port']} is not master for device {device_id}")
                            continue
                    else:
                        logger.warning(f"Failed to check mastership on {ctrl['ip']}:{ctrl['port']}")
                        continue
                except requests.RequestException as e:
                    logger.warning(f"Mastership check failed for {ctrl['ip']}:{ctrl['port']}: {e}")
                    continue

            # Send the actual request
            url = f"http://{ctrl['ip']}:{ctrl['port']}{endpoint}"
            logger.info(f"Sending {method.upper()} request to {url}")
            
            resp = requests.request(method, url, auth=AUTH, timeout=5, data=data, json=json)
            
            if resp.ok:
                # Return JSON if content type is JSON, otherwise return text
                if resp.headers.get("Content-Type", "").startswith("application/json"):
                    return resp.json()
                else:
                    return {"status": "success", "message": resp.text}
            else:
                logger.warning(f"Request failed with status {resp.status_code}: {resp.text}")
                
        except requests.RequestException as e:
            logger.warning(f"Request to {ctrl['ip']}:{ctrl['port']} failed: {e}")
            time.sleep(0.1)  # Small delay before trying next controller
            continue
    
    return {"error": "All controllers unreachable or not master for this device"}


# === Action: Get Devices ===
#### Works ####
class ActionGetDevices(Action):
    def name(self) -> str:
        return "action_get_devices"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[str, Any]) -> List[EventType]:
        logger.info("Getting devices from ONOS")
        result = send_to_healthy_controller("/onos/v1/devices")
        
        if "error" in result:
            dispatcher.utter_message(text="❌ Could not reach any ONOS controller to fetch devices.")
        else:
            devices = result.get("devices", [])
            if devices:
                device_list = []
                for device in devices:
                    device_id = device.get("id", "Unknown")
                    device_type = device.get("type", "Unknown")
                    available = "✅" if device.get("available", False) else "❌"
                    device_list.append(f"{available} {device_id} ({device_type})")
                
                message = f"🖧 Number of Connected Devices: ({len(devices)}):\n" + "\n".join(device_list)
                dispatcher.utter_message(text=message)
            else:
                dispatcher.utter_message(text="📭 No devices found in the network.")
        
        return []


# === Action: Add Flow ===
class ActionAddFlow(Action):
    def name(self) -> Text:
        return "action_add_flow"

    def extract_slot(self, slot_name, tracker):
        value = tracker.get_slot(slot_name)
        return value.strip() if value else None

    def find_master_controller(self, device_id):
        controller_ips = ["10.0.0.21", "10.0.0.22", "10.0.0.23", "10.0.0.24", "10.0.0.25"]
        for ip in controller_ips:
            url = f"http://{ip}:8181/onos/v1/devices/{device_id}"
            try:
                response = requests.get(url, auth=('onos', 'rocks'))
                if response.status_code == 200:
                    data = response.json()
                    if data.get("role") == "MASTER":
                        return ip
            except Exception as e:
                continue
        return None

    async def run(self, dispatcher, tracker, domain):
        device_id = self.extract_slot("device_id", tracker)
        in_port = self.extract_slot("in_port", tracker)
        out_port = self.extract_slot("out_port", tracker)
        priority = self.extract_slot("priority", tracker)

        if not all([device_id, in_port, out_port, priority]):
            dispatcher.utter_message(text="⚠️ Missing values: device ID, input/output ports, or priority. Please provide all required details.")
            return []

        master_ip = self.find_master_controller(device_id)
        if not master_ip:
            dispatcher.utter_message(text=f"❌ Could not find any MASTER controller for {device_id}. Check controller status or device connection.")
            return []

        flow_payload = {
            "priority": int(priority),
            "timeout": 0,
            "isPermanent": True,
            "deviceId": device_id,
            "treatment": {
                "instructions": [{"type": "OUTPUT", "port": out_port}]
            },
            "selector": {
                "criteria": [{"type": "IN_PORT", "port": in_port}]
            }
        }

        url = f"http://{master_ip}:8181/onos/v1/flows/{device_id}"
        headers = {"Content-Type": "application/json"}
        try:
            response = requests.post(url, auth=('onos', 'rocks'), headers=headers, data=json.dumps(flow_payload))
            if response.status_code in [200, 201, 204]:
                dispatcher.utter_message(text=f"✅ Flow added successfully to {device_id} from port {in_port} to port {out_port} with priority {priority}")
            else:
                dispatcher.utter_message(text=f"❌ Failed to install flow rule on {device_id}. Status code: {response.status_code}")
        except Exception as e:
            dispatcher.utter_message(text=f"❌ Error occurred: {e}")

        return []

# === Action: Get Controller Status ===
#### Works ####
class ActionCheckControllers(Action):
    def name(self):
        return "action_check_controllers"

    def run(self, dispatcher, tracker, domain):
        reachable = []
        unreachable = []

        for ctrl in ONOS_CONTROLLERS:
            url = f"http://{ctrl['ip']}:{ctrl['port']}/onos/v1/cluster"
            try:
                response = requests.get(url, auth=AUTH, timeout=3)
                if response.status_code == 200:
                    reachable.append(f"{ctrl['ip']}:{ctrl['port']}")
                else:
                    unreachable.append(f"{ctrl['ip']}:{ctrl['port']}")
            except Exception:
                unreachable.append(f"{ctrl['ip']}:{ctrl['port']}")

        # Format the response
        if reachable:
            dispatcher.utter_message(text="🟢 **Reachable Controllers:**\n" + "\n".join(reachable))
        if unreachable:
            dispatcher.utter_message(text="🔴 **Unreachable Controllers:**\n" + "\n".join(unreachable))

        return []

# === Action: Default Fallback ===
#### Works ####
class ActionDefaultFallback(Action):
    def name(self) -> str:
        return "action_default_fallback"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[str, Any]) -> List[EventType]:
        dispatcher.utter_message(text="🤔 Sorry, I didn't understand that. I can help you with:\n"
                                     "• Show devices, hosts, ports, flows\n"
                                     "• Add flow rules\n"
                                     "• Block/unblock hosts\n"
                                     "• Check controller status\n"
                                     "• Display network topology\n\n"
                                     "Try asking something like 'show all devices' or 'check controllers'")
        return []


# === Action: Get Hosts ===
#### Works ####
class ActionGetHosts(Action):
    def name(self) -> str:
        return "action_get_hosts"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[str, Any]) -> List[EventType]:
        logger.info("Getting hosts from ONOS")
        result = send_to_healthy_controller("/onos/v1/hosts")

        if "error" in result:
            dispatcher.utter_message(text="❌ Could not fetch hosts from any controller.")
        else:
            hosts = result.get("hosts", [])
            if hosts:
                host_list = []
                for host in hosts:
                    host_id = host.get("id", "Unknown")
                    mac = host.get("mac", "Unknown")
                    ip = host.get("ipAddresses", ["Unknown"])[0] if host.get("ipAddresses") else "Unknown"
                    location_obj = host.get("location", {})
                    element_id = location_obj.get("elementId", "Unknown")
                    port = location_obj.get("port", "Unknown")

                    host_list.append(f"🏠 {host_id} (MAC: {mac}, IP: {ip})")

                message = f"🏠 Number of Network Hosts ({len(hosts)}):\n" + "\n".join(host_list)
                dispatcher.utter_message(text=message)
            else:
                dispatcher.utter_message(text="📭 No hosts found in the network.")

        return []

# === Action: Block Host ===
class ActionBlockHost(Action):
    def name(self) -> Text:
        return "action_block_host"

    def run(self, dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:

        host_id = tracker.get_slot("host_id")

        if not host_id:
            dispatcher.utter_message(text="⚠️ Please provide a valid host MAC address.")
            return []

        for controller in ONOS_CONTROLLERS:
            ip = controller["ip"]
            port = controller["port"]
            base_url = f"http://{ip}:{port}/onos/v1"
            auth = ("onos", "rocks")
            master_found = False

            try:
                # 1. Get ONOS cluster nodes
                response = requests.get(f"{base_url}/cluster/nodes", auth=auth, timeout=2)
                if response.status_code == 200:
                    nodes = response.json()
                    for node in nodes:
                        # Match using controller port in the node ID
                        if str(port) in node.get("id", "") and node.get("role") == "MASTER":
                            master_found = True
                            break

                if not master_found:
                    continue

                # 2. Get host info
                host_response = requests.get(f"{base_url}/network/hosts", auth=auth, timeout=2)
                if host_response.status_code != 200:
                    continue

                hosts = host_response.json()
                matched_host = next((h for h in hosts if h["mac"] == host_id), None)

                if not matched_host:
                    dispatcher.utter_message(text=f"❌ Host {host_id} not found.")
                    return []

                location = matched_host["locations"][0]
                device_id = location["elementId"]
                port_num = location["port"]

                flow_rule = {
                    "priority": 40000,
                    "timeout": 0,
                    "isPermanent": True,
                    "deviceId": device_id,
                    "treatment": {},
                    "selector": {
                        "criteria": [
                            {
                                "type": "ETH_DST",
                                "mac": host_id
                            }
                        ]
                    }
                }

                # 3. Push flow to block host
                flow_url = f"{base_url}/flows/{device_id}"
                flow_response = requests.post(flow_url, json=flow_rule, auth=auth, timeout=2)

                if flow_response.status_code in [200, 201, 204]:
                    dispatcher.utter_message(text=f"🚫 Host {host_id} has been blocked on {device_id}.")
                    return []

            except Exception as e:
                print(f"[ERROR] Failed for controller {ip}:{port} - {e}")
                continue

        dispatcher.utter_message(text=f"❌ Failed to block host {host_id}. All controllers unreachable or not master for this device.")
        return []

# === Action: Unblock Host ===
class ActionUnblockHost(Action):
    def name(self) -> str:
        return "action_unblock_host"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[str, Any]) -> List[EventType]:
        host_id = tracker.get_slot("host_id")
        if not host_id:
            dispatcher.utter_message(text="⚠️ Please specify a host ID to unblock (e.g., 'unblock host AA:BB:CC:DD:EE:FF')")
            return []
        
        logger.info(f"Unblocking host: {host_id}")
        result = send_to_healthy_controller(f"/onos/v1/acl/allow/{host_id}", method="post")
        
        if "error" in result:
            dispatcher.utter_message(text=f"❌ Failed to unblock host {host_id}. {result.get('error', '')}")
        else:
            dispatcher.utter_message(text=f"✅ Host {host_id} has been unblocked successfully.")
        
        return []


# === Action: Get Ports ===
class ActionGetPorts(Action):
    def name(self) -> str:
        return "action_get_ports"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[str, Any]) -> List[EventType]:
        device_id = tracker.get_slot("device_id")
        if not device_id:
            dispatcher.utter_message(text="⚠️ Please specify a device ID (e.g., 'show ports on device of:0000000000000001')")
            return []
        
        logger.info(f"Getting ports for device: {device_id}")
        result = send_to_healthy_controller(f"/onos/v1/devices/{device_id}/ports")
        
        if "error" in result:
            dispatcher.utter_message(text=f"❌ Failed to fetch ports for device {device_id}.")
        else:
            ports = result.get("ports", [])
            if ports:
                port_list = []
                for port in ports:
                    port_num = port.get("port", "Unknown")
                    enabled = "✅" if port.get("isEnabled", False) else "❌"
                    speed = port.get("portSpeed", "Unknown")
                    port_list.append(f"{enabled} Port {port_num} (Speed: {speed})")
                
                message = f"🔌 **Ports on {device_id} ({len(ports)}):**\n" + "\n".join(port_list)
                dispatcher.utter_message(text=message)
            else:
                dispatcher.utter_message(text=f"📭 No ports found on device {device_id}.")
        
        return []


# === Action: Get Flows ===
#### Works ####
class ActionGetFlows(Action):
    def name(self) -> str:
        return "action_get_flows"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[str, Any]) -> List[EventType]:
        device_id = tracker.get_slot("device_id")

        # Fallback: extract from raw text if NLU missed it
        if not device_id:
            user_text = tracker.latest_message.get("text", "")
            import re
            match = re.search(r"(of:[0-9a-fA-F]+)", user_text)
            if match:
                device_id = match.group(1)

        if not device_id:
            dispatcher.utter_message(text="⚠️ Please specify a device ID (e.g., 'show flows on device of:0000000000000001')")
            return []

        logger.info(f"Getting flows for device: {device_id}")
        result = send_to_healthy_controller(f"/onos/v1/flows/{device_id}")

        if "error" in result:
            dispatcher.utter_message(text=f"❌ Failed to fetch flows for device {device_id}.")
        else:
            flows = result.get("flows", [])
            if flows:
                flow_list = []
                for flow in flows:
                    flow_id = flow.get("id", "Unknown")[:8]  # Truncate for readability
                    priority = flow.get("priority", "Unknown")
                    state = flow.get("state", "Unknown")
                    flow_list.append(f"🔁 {flow_id}... (Priority: {priority}, State: {state})")

                message = f"🔁 **Flows on {device_id} ({len(flows)}):**\n" + "\n".join(flow_list)
                dispatcher.utter_message(text=message)
            else:
                dispatcher.utter_message(text=f"📭 No flows found on device {device_id}.")

        return []

# === Action: Show Topology ===
#### Works ####
class ActionShowTopology(Action):
    def name(self) -> str:
        return "action_show_topology"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[str, Any]) -> List[EventType]:
        logger.info("Fetching full topology details")

        devices_resp = send_to_healthy_controller("/onos/v1/devices")
        hosts_resp = send_to_healthy_controller("/onos/v1/hosts")
        links_resp = send_to_healthy_controller("/onos/v1/links")
        cluster_nodes_resp = send_to_healthy_controller("/onos/v1/cluster/nodes")

        device_count = len(devices_resp.get("devices", [])) if isinstance(devices_resp, dict) else 0
        host_count = len(hosts_resp.get("hosts", [])) if isinstance(hosts_resp, dict) else 0
        link_count = len(links_resp.get("links", [])) if isinstance(links_resp, dict) else 0

        if isinstance(cluster_nodes_resp, dict) and "nodes" in cluster_nodes_resp:
            nodes = cluster_nodes_resp.get("nodes", [])
            cluster_count = 1 if len(nodes) > 0 else 0
        else:
            cluster_count = 0

        message = (
            f"🌐 **Real-Time Network Topology:**\n"
            f"📱 Devices: {device_count}\n"
            f"🔗 Links: {link_count}\n"
            f"🏠 Hosts: {host_count}\n"
        )

        dispatcher.utter_message(text=message)
        return []
