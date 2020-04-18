from libnmap.parser import NmapParser
LOCALHOST_IP = "127.0.0.1"

def get_scan_data(filename):
    """Read XML file and parse scan data into JSON format able to be used with VIS.js and flask frontend.
    """
    if filename is None:
        return {}
    try:
        nmap_report = NmapParser.parse_fromfile(filename)
    except:
        return False

    scan_data = {} 
    for current_host in nmap_report.hosts:
        host = {}
        host["address"] = current_host.address
        host["hostnames"] = current_host.hostnames
        host["status"] = current_host.status
        host["os"] = current_host.os
        host["osmatch"] = [(osmatch.name, osmatch.accuracy) for osmatch in current_host.os.osmatches]
        host["osmatch"].reverse()
        host["is_up"] = current_host.is_up()
        services = [] 
        for service in current_host.services:
            serv = {}
            serv["port"] = str(service.port)
            serv["protocol"] = service.protocol
            serv["service"] = service.service
            serv["state"] = service.state
            services.append(serv)

        host["services"] = services
        scan_data[current_host.address] = host

    return scan_data

def get_os_type(os_data):
    """Decide on OS type and assign appropriate icon
    """
    data = {}
    data["server"] = ('\uf233', '"Font Awesome 5 Free"')
    data["linux"] = ('\uf17c', '"Font Awesome 5 Brands"')
    data["windows"] = ('\uf17a', '"Font Awesome 5 Brands"')    
    data["bsd"] = ('\uf3a4', '"Font Awesome 5 Brands"')
    data["ubuntu"] = ('\uf7df', '"Font Awesome 5 Brands"')
    data["suse"] = ('\uf7d6', '"Font Awesome 5 Brands"')
    data["redhat"] = ('\uf7bc', '"Font Awesome 5 Brands"')
    data["fedora"] = ('\uf798', '"Font Awesome 5 Brands"')
    data["centos"] = ('\uf789', '"Font Awesome 5 Brands"')
    data["apple"] = ('\uf179', '"Font Awesome 5 Brands"')
    data["android"] = ('\uf17b', '"Font Awesome 5 Brands"')                

    retval = data["server"]
    match_data = os_data
    match_data.reverse()
    # use reverse order so the last match we make is the most accurate
    for match, _ in match_data:
        if "linux" in match.lower():
            retval = data["linux"]
        if "windows" in match.lower():
            retval = data["windows"]
        if "bsd" in match.lower():
            retval = data["bsd"]
        if "ubuntu" in match.lower():
            retval = data["ubuntu"]
        if "suse" in match.lower():
            retval = data["suse"]
        if "redhat" in match.lower():
            retval = data["redhat"]
        if "centos" in match.lower():
            retval = data["centos"]
        if "apple" in match.lower():
            retval = data["apple"]
        if "android" in match.lower():
            retval = data["apple"]            

    return retval

def get_graph_data(host_data):
    """Create dictionaries containing the nodes and edges between them,
    that can be used by VIS.js to display the data.
    """
    network_nodes = []
    network_edges = []
    localhost_in_data = False
    for host, data in host_data.items():
        if data["is_up"] == False:
            continue
        if host == "127.0.0.1":
            localhost_in_data = True

        node = {}
        node["id"] = host

        if "hostnames" in data and len(data["hostnames"]) != 0:
            node["label"] = data["hostnames"][0]
        else:
            node["label"] = host

        node["shape"] = "dot"
        node["icon"] = {
            "face": '"Font Awesome 5 Free"',
            "code": '\uf233',
        }

        if "osmatch" in data:
            code, face = get_os_type(data["osmatch"])
            node["icon"]["code"] = code
            node["icon"]["face"] = face
        network_nodes.append(node)

        edge = {}
        edge["from"] = LOCALHOST_IP
        edge["to"] = host
        edge["value"] = len(data["services"])
        network_edges.append(edge)

    if not localhost_in_data:
        localhost_node = {}
        localhost_node["id"] = LOCALHOST_IP
        localhost_node["label"] = LOCALHOST_IP
        localhost_node["shape"] = "dot"
        localhost_node["icon"] = {
            "face": '"Font Awesome 5 Free"',
            "code": '\uf015',
        }
        network_nodes.append(localhost_node)

    return (network_nodes, network_edges)

def parse_xml_stats(filename):
    """Get the basic information/metadata about the scan.
    """
    stats = {}
    if filename is None:
        return stats

    nmap_report = NmapParser.parse_fromfile(filename)
    stats["elapsed"] = nmap_report.elapsed
    stats["commandline"] = nmap_report.commandline
    stats["hosts"] = "{}/{}".format(nmap_report.hosts_up, nmap_report.hosts_total)
    stats["hosts_up"] = nmap_report.hosts_up    
    stats["report_version"] = nmap_report.version
    # scan info is not present on -sn scan
    if nmap_report._scaninfo:
        stats["scan_type"] = nmap_report.scan_type

    return stats