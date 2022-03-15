if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103996" );
	script_version( "2021-03-19T08:40:35+0000" );
	script_tag( name: "last_modification", value: "2021-03-19 08:40:35 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2011-04-05 14:24:03 +0200 (Tue, 05 Apr 2011)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Gather Linux Hardware Information" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script attempts to gather information about the hardware configuration
  from a linux host and stores the results in the KB." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("host_details.inc.sc");
require("ssh_func.inc.sc");
SCRIPT_DESC = "Gather Linux Hardware Information";
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
cpuinfo = ssh_cmd( socket: sock, cmd: "cat /proc/cpuinfo" );
cpus = make_array();
cpunumber = 0;
if( IsMatchRegexp( cpuinfo, "Hardware.*: " ) ) {
	cpu_regex = "^(Hardware.*: )(.*)$";
}
else {
	cpu_regex = "^(model name.*: )(.*)$";
}
for line in split( cpuinfo ) {
	if(IsMatchRegexp( line, "^processor.*: " )){
		cpunumber++;
		continue;
	}
	line = chomp( line );
	v = eregmatch( string: line, pattern: cpu_regex, icase: TRUE );
	if(!isnull( v )){
		if( isnull( cpus[v[2]] ) ){
			cpus[v[2]] = 1;
		}
		else {
			cpus[v[2]]++;
		}
	}
}
archinfo = ssh_cmd( socket: sock, cmd: "uname -m" );
arch = "";
if(egrep( string: archinfo, pattern: "^(x86_64|i386|i486|i586|i686|sun4u|unknown|armv7l|armv8|ia64|alpha|amd64|arm|armeb|armel|hppa|m32r|m68k|mips|mipsel|powerpc|ppc64|s390|s390x|sh3|sh3eb|sh4|sh4eb|sparc)$" )){
	arch = archinfo;
	set_kb_item( name: "ssh/login/arch", value: arch );
}
lspci = ssh_cmd( socket: sock, cmd: "/usr/bin/lspci -vmm" );
if(lspci){
	lspci_lines = split( buffer: lspci, keep: FALSE );
	max = max_index( lspci_lines );
	if(max > 2){
		set_kb_item( name: "ssh_or_wmi/login/pci_devices/available", value: TRUE );
		set_kb_item( name: "ssh/login/pci_devices/available", value: TRUE );
		device_infos = make_array();
		for(i = 0;i < max;i++){
			if(lspci_lines[i] == ""){
				continue;
			}
			entry = split( buffer: lspci_lines[i], sep: ":\t", keep: FALSE );
			device_infos[entry[0]] = entry[1];
			if(( lspci_lines[i + 1] == "" ) || ( i == max - 1 )){
				deviceid = device_infos["Slot"];
				if(!deviceid){
					deviceid = "unknown";
				}
				set_kb_item( name: "ssh/login/pci_devices/device_ids", value: deviceid );
				for device_info in keys( device_infos ) {
					set_kb_item( name: "ssh/login/pci_devices/" + deviceid + "/" + tolower( device_info ), value: device_infos[device_info] );
				}
				device_infos = make_array();
			}
		}
	}
}
meminfo = ssh_cmd( socket: sock, cmd: "cat /proc/meminfo" );
memtotal = "";
for line in split( buffer: meminfo, keep: FALSE ) {
	v = eregmatch( string: line, pattern: "^(MemTotal:[ ]+)([0-9]+ kB)$", icase: TRUE );
	if(!isnull( v )){
		memtotal = v[2];
		break;
	}
}
ifconfig = ssh_cmd( socket: sock, cmd: "/sbin/ifconfig" );
interfaces = split( buffer: ifconfig, sep: "\r\n\r\n", keep: FALSE );
netinfo = "";
host_ip = get_host_ip();
for interface in interfaces {
	x = 0;
	ip_str = "";
	if(ContainsString( interface, "Loopback" )){
		continue;
	}
	lines = split( interface );
	for line in lines {
		v = eregmatch( string: line, pattern: "^[^ ].*|.*inet[6]? addr.*|^$" );
		if(!isnull( v )){
			netinfo += v[0];
		}
		if(ContainsString( line, "HWaddr" )){
			mac = eregmatch( pattern: "HWaddr ([0-9a-fA-F:]{17})", string: line );
			nic = eregmatch( pattern: "(^[^ ]+)", string: line );
			z = x + 1;
			for(;ip = eregmatch( pattern: "inet[6]? addr:[ ]?([^ ]+)", string: lines[z] );){
				if(!isnull( ip[1] )){
					ip_str += ip[1] + ";";
				}
				z++;
			}
			ip_str = substr( ip_str, 0, strlen( ip_str ) - 2 );
			if( !isnull( mac ) ){
				num_ifaces++;
				replace_kb_item( name: "ssh/login/net_iface/num_ifaces", value: num_ifaces );
				if(ContainsString( lines[x + 1], host_ip )){
					register_host_detail( name: "MAC", value: mac[1], desc: SCRIPT_DESC );
					set_kb_item( name: "ssh/login/net_iface/" + num_ifaces + "/iface_mac", value: mac[1] );
					if(!isnull( nic[1] )){
						target_nic = nic[1];
						register_host_detail( name: "NIC", value: nic[1], desc: SCRIPT_DESC );
						set_kb_item( name: "ssh/login/net_iface/" + num_ifaces + "/iface_name", value: nic[1] );
						if(strlen( ip_str ) > 0){
							register_host_detail( name: "NIC_IPS", value: ip_str, desc: SCRIPT_DESC );
							set_kb_item( name: "ssh/login/net_iface/" + num_ifaces + "/iface_ips", value: ip_str );
						}
					}
				}
				if(!isnull( nic[1] ) && nic[1] != target_nic){
					set_kb_item( name: "ssh/login/net_iface/" + num_ifaces + "/iface_mac", value: mac[1] );
					set_kb_item( name: "ssh/login/net_iface/" + num_ifaces + "/iface_name", value: nic[1] );
					set_kb_item( name: "ssh/login/net_iface/" + num_ifaces + "/iface_ips", value: ip_str );
					register_host_detail( name: "MAC-Ifaces", value: nic[1] + "|" + mac[1] + "|" + ip_str, desc: SCRIPT_DESC );
				}
			}
			else {
				iv_mac = eregmatch( pattern: "HWaddr ([^ \\n]+)", string: line );
				if(!isnull( iv_mac[1] ) && !isnull( nic[1] )){
					register_host_detail( name: "BROKEN_MAC-Iface", value: nic[1] + "|" + iv_mac[1] + "|" + ip_str, desc: SCRIPT_DESC );
				}
			}
		}
		x++;
	}
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
if(archinfo != ""){
	register_host_detail( name: "archinfo", value: archinfo, desc: SCRIPT_DESC );
}
if(memtotal != ""){
	register_host_detail( name: "meminfo", value: memtotal, desc: SCRIPT_DESC );
}
if(netinfo != ""){
	register_host_detail( name: "netinfo", value: netinfo, desc: SCRIPT_DESC );
}
exit( 0 );

