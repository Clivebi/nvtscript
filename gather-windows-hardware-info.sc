if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107304" );
	script_version( "2020-11-12T10:28:08+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 10:28:08 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2018-04-11 16:48:58 +0200 (Wed, 11 Apr 2018)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Gather Windows Hardware Information" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "gb_wmi_access.sc", "smb_reg_service_pack.sc" );
	script_mandatory_keys( "WMI/access_successful" );
	script_tag( name: "summary", value: "This script attempts to gather information about the hardware configuration
  from a windows host and stores the results in the KB." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
SCRIPT_DESC = "Gather Windows Hardware Information";
require("host_details.inc.sc");
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("wmi_os.inc.sc");
host = get_host_ip();
usrname = kb_smb_login();
passwd = kb_smb_password();
if(!host || !usrname || !passwd){
	exit( 0 );
}
domain = kb_smb_domain();
if(domain){
	usrname = domain + "\\" + usrname;
}
handle = wmi_connect( host: host, username: usrname, password: passwd );
if(!handle){
	exit( 0 );
}
query1 = "SELECT * FROM Win32_Processor";
processor_infos = wmi_query( wmi_handle: handle, query: query1 );
if( processor_infos && ContainsString( processor_infos, "NumberOfCores" ) ){
	query1 = "SELECT DeviceID, Name, NumberOfCores FROM Win32_Processor";
	header = "DeviceID|Name|NumberOfCores";
	processor_infos = wmi_query( wmi_handle: handle, query: query1 );
}
else {
	if(processor_infos){
		query1 = "SELECT DeviceID, Name FROM Win32_Processor";
		header = "DeviceID|Name";
		processor_infos = wmi_query( wmi_handle: handle, query: query1 );
	}
}
cpunumber = 0;
cpus = make_array();
if(processor_infos){
	info_list = split( buffer: processor_infos, keep: FALSE );
	for info in info_list {
		if(info == header){
			continue;
		}
		cpunumber++;
		info_split = split( buffer: info, sep: "|", keep: FALSE );
		proc_name = info_split[1];
		num_cores = int( info_split[2] );
		if(!num_cores){
			num_cores = 1;
		}
		if( isnull( cpus[proc_name] ) ){
			cpus[proc_name] = num_cores;
		}
		else {
			cpus[proc_name] += num_cores;
		}
	}
}
query2 = "SELECT * FROM Win32_OperatingSystem";
arch_infos = wmi_query( wmi_handle: handle, query: query2 );
arch = "";
if( arch_infos && ContainsString( arch_infos, "OSArchitecture" ) ){
	query2 = "SELECT OSArchitecture FROM Win32_OperatingSystem";
	arch_infos = wmi_query( wmi_handle: handle, query: query2 );
}
else {
	_arch = get_kb_item( "SMB/Windows/Arch" );
	if( _arch && _arch == "x64" ){
		arch = "64-bit";
	}
	else {
		if( _arch && _arch == "x86" ){
			arch = "32-bit";
		}
		else {
			arch = "unknown";
		}
	}
	arch_infos = "";
	set_kb_item( name: "wmi/login/arch", value: arch );
}
if(arch_infos){
	info_list = split( buffer: arch_infos, keep: FALSE );
	for info in info_list {
		if(info == "OSArchitecture"){
			continue;
		}
		arch = info;
		set_kb_item( name: "wmi/login/arch", value: arch );
	}
}
query3 = "SELECT DeviceID, Manufacturer, Name FROM Win32_PNPEntity WHERE DeviceID LIKE '%PCI\\\\VEN_%' ";
pci_devices = wmi_query( wmi_handle: handle, query: query3 );
if(pci_devices){
	deviceid = 0;
	pci_list = split( buffer: pci_devices, keep: FALSE );
	for pcidevice in pci_list {
		if(pcidevice == "DeviceID|Manufacturer|Name" || pcidevice == ""){
			continue;
		}
		deviceid++;
		pcidevice_split = split( buffer: pcidevice, sep: "|", keep: FALSE );
		manufacturer = pcidevice_split[1];
		name = pcidevice_split[2];
		set_kb_item( name: "ssh_or_wmi/login/pci_devices/available", value: TRUE );
		set_kb_item( name: "wmi/login/pci_devices/available", value: TRUE );
		set_kb_item( name: "wmi/login/pci_devices/device_ids", value: deviceid );
		set_kb_item( name: "wmi/login/pci_devices/" + deviceid + "/slot", value: deviceid );
		set_kb_item( name: "wmi/login/pci_devices/" + deviceid + "/vendor", value: manufacturer );
		set_kb_item( name: "wmi/login/pci_devices/" + deviceid + "/device", value: name );
	}
}
query4 = "SELECT Name, TotalPhysicalMemory FROM Win32_Computersystem";
memory = wmi_query( wmi_handle: handle, query: query4 );
meminfo = "";
if(memory){
	mem_list = split( buffer: memory, keep: FALSE );
	for mem in mem_list {
		if(mem == "Name|TotalPhysicalMemory"){
			continue;
		}
		mem_split = split( buffer: mem, sep: "|", keep: FALSE );
		memtotal = mem_split[1];
		_memtotal = int( memtotal );
		if( _memtotal < 0 ){
			meminfo = memtotal + " B";
		}
		else {
			if( _memtotal > 0 ){
				meminfo = ( _memtotal / 1024 ) + " kB";
			}
			else {
				meminfo = "unknown";
			}
		}
	}
}
query5 = "SELECT Description, Index, IPAddress, MACAddress FROM Win32_NetworkAdapterConfiguration";
addresses = wmi_query( wmi_handle: handle, query: query5 );
num_ifaces = 0;
host_ip = get_host_ip();
if(addresses){
	addr_list = split( buffer: addresses, keep: FALSE );
	for address in addr_list {
		if(address == "Description|Index|IPAddress|MACAddress"){
			continue;
		}
		iface_ipstr = "";
		addr_split = split( buffer: address, sep: "|", keep: FALSE );
		iface_name = addr_split[0];
		for(i = 2;i < max_index( addr_split ) - 1;i++){
			if(addr_split[i] != "(null)"){
				iface_ipstr += addr_split[i] + ";";
			}
		}
		iface_mac = addr_split[max_index( addr_split ) - 1];
		iface_mac = eregmatch( pattern: "([0-9a-fA-F:]{17})", string: iface_mac );
		if( !isnull( iface_mac ) ){
			num_ifaces++;
			replace_kb_item( name: "wmi/login/net_iface/num_ifaces", value: num_ifaces );
			if(ContainsString( iface_ipstr, host_ip )){
				register_host_detail( name: "MAC", value: iface_mac[1], desc: SCRIPT_DESC );
				set_kb_item( name: "wmi/login/net_iface/" + num_ifaces + "/iface_mac", value: iface_mac[1] );
				if(iface_name != ""){
					target_nic = iface_name;
					register_host_detail( name: "NIC", value: iface_name, desc: SCRIPT_DESC );
					set_kb_item( name: "wmi/login/net_iface/" + num_ifaces + "/iface_name", value: iface_name );
					if(strlen( iface_ipstr ) > 0){
						register_host_detail( name: "NIC_IPS", value: iface_ipstr, desc: SCRIPT_DESC );
						set_kb_item( name: "wmi/login/net_iface/" + num_ifaces + "/iface_ips", value: iface_ipstr );
					}
				}
			}
			if(iface_name != "" && iface_name != target_nic){
				set_kb_item( name: "wmi/login/net_iface/" + num_ifaces + "/iface_mac", value: iface_mac[1] );
				set_kb_item( name: "wmi/login/net_iface/" + num_ifaces + "/iface_name", value: iface_name );
				set_kb_item( name: "wmi/login/net_iface/" + num_ifaces + "/iface_ips", value: iface_ipstr );
				register_host_detail( name: "MAC-Ifaces", value: iface_name + "|" + iface_mac[1] + "|" + iface_ipstr, desc: SCRIPT_DESC );
			}
		}
		else {
			if(iface_mac != "" && iface_name != ""){
				register_host_detail( name: "BROKEN_MAC-Iface", value: iface_name + "|" + iface_mac + "|" + iface_ipstr, desc: SCRIPT_DESC );
			}
		}
	}
}
if(num_ifaces > 0){
	query6 = "SELECT * FROM Win32_NetworkAdapterConfiguration";
	full_netinfo = wmi_query( wmi_handle: handle, query: query6 );
}
netinfo = "";
wmi_close( wmi_handle: handle );
if(full_netinfo){
	netinfo = full_netinfo;
}
if(cpunumber){
	cpu_str = "";
	for cputype in keys( cpus ) {
		if(cpu_str != ""){
			cpu_str += "\n";
		}
		cpu_str += NASLString( cpus[cputype], " ", cputype );
	}
	register_host_detail( name: "cpuinfo", value: cpu_str, desc: SCRIPT_DESC );
}
if(arch != ""){
	register_host_detail( name: "archinfo", value: arch, desc: SCRIPT_DESC );
}
if(meminfo != ""){
	register_host_detail( name: "meminfo", value: meminfo, desc: SCRIPT_DESC );
}
if(netinfo != ""){
	register_host_detail( name: "netinfo", value: netinfo, desc: SCRIPT_DESC );
}
exit( 0 );

