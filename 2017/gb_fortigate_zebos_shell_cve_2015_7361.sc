if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140112" );
	script_version( "2021-07-12T08:06:48+0000" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2015-7361" );
	script_name( "Fortinet FortiGate ZebOS routing remote shell service enabled (FG-IR-15-020)" );
	script_xref( name: "URL", value: "https://www.fortiguard.com/psirt/FG-IR-15-020" );
	script_tag( name: "vuldetect", value: "Open a connection to port 2650 and execute the `show version`
  command." );
	script_tag( name: "insight", value: "A remote attacker may access the internal ZebOS shell of FortiOS
  5.2.3 without authentication on the HA dedicated management interface only.

  Only FortiGates configured with HA *and* with an enabled HA dedicated management interface are
  vulnerable." );
	script_tag( name: "solution", value: "Update FortiOS to version 5.2.4 or later." );
	script_tag( name: "summary", value: "The Fortinet FortiGate device has the ZebOS routing remote shell
  service enabled." );
	script_tag( name: "affected", value: "FortiGate version 5.2.3 only." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "last_modification", value: "2021-07-12 08:06:48 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2017-01-02 12:27:55 +0100 (Mon, 02 Jan 2017)" );
	script_category( ACT_ATTACK );
	script_family( "Gain a shell remotely" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/zebos_routing_shell" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
if(!port = service_get_port( proto: "zebos_routing_shell", nodefault: TRUE )){
	exit( 0 );
}
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
recv = recv( socket: soc, length: 128 );
if(!ContainsString( recv, "ZebOS" )){
	close( soc );
	exit( 99 );
}
send( socket: soc, data: "show version\n" );
recv = recv( socket: soc, length: 512 );
close( soc );
if(ContainsString( recv, "ZebOS version" ) && ContainsString( recv, "IP Infusion Inc" )){
	report = "The ZebOS routing remote shell is accessible at this port without authentication. Running \"show version\" gives the following output:\n" + recv + "\n";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

