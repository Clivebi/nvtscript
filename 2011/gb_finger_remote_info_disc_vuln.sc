if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802236" );
	script_version( "2021-01-20T08:41:35+0000" );
	script_tag( name: "last_modification", value: "2021-01-20 08:41:35 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "creation_date", value: "2011-08-12 14:44:50 +0200 (Fri, 12 Aug 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Finger Service Remote Information Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "find_service.sc", "find_service1.sc", "find_service2.sc" );
	script_require_ports( "Services/finger", 79 );
	script_xref( name: "URL", value: "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0612" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/46" );
	script_xref( name: "URL", value: "http://www.iss.net/security_center/reference/vuln/finger-running.htm" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to obtain sensitive information
  that could aid in further attacks." );
	script_tag( name: "affected", value: "GNU finger is known to be affected. Other finger implementations might be
  affected as well." );
	script_tag( name: "insight", value: "The flaw exists because the finger service exposes valid user information to any
  entity on the network." );
	script_tag( name: "summary", value: "The finger service on the remote host is prone to an information disclosure vulnerability." );
	script_tag( name: "solution", value: "Disable the finger service, or install a finger service or daemon that
  limits the type of information provided." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 79, proto: "finger" );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
banner = recv( socket: soc, length: 2048, timeout: 5 );
if(banner){
	close( soc );
	exit( 0 );
}
send( socket: soc, data: NASLString( "root\\r\\n" ) );
res = recv( socket: soc, length: 2048 );
close( soc );
if(!res){
	exit( 0 );
}
if(ContainsString( res, "Login" ) || ContainsString( res, "User" ) || ContainsString( res, "logged" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

