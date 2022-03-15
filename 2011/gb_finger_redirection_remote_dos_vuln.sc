if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802231" );
	script_version( "2021-01-20T08:41:35+0000" );
	script_tag( name: "last_modification", value: "2021-01-20 08:41:35 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "creation_date", value: "2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)" );
	script_cve_id( "CVE-1999-0106" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Finger Redirection Remote Denial of Service Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc", "find_service1.sc", "find_service2.sc" );
	script_require_ports( "Services/finger", 79 );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/47" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?id=10073" );
	script_xref( name: "URL", value: "http://www.iss.net/security_center/reference/vuln/finger-bomb.htm" );
	script_tag( name: "summary", value: "The finger service on the remote host is prone to a Denial of Service (DoS)
  vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker to use this computer as a relay
  to gather information on a third-party network or cause a denial of service." );
	script_tag( name: "affected", value: "GNU finger is known to be affected. Other finger implementations might be
  affected as well." );
	script_tag( name: "insight", value: "The flaw exists because the finger daemon allows redirecting a finger request
  to remote sites using the form finger 'username@hostname1@hostname2'." );
	script_tag( name: "solution", value: "Update to GNU finger 1.37 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 79, proto: "finger" );
host = get_host_name();
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
banner = recv( socket: soc, length: 2048, timeout: 5 );
if(banner){
	close( soc );
	exit( 0 );
}
req = "root@" + host + "\\r\\n";
send( socket: soc, data: req );
res = recv( socket: soc, length: 65535 );
close( soc );
if(!res){
	exit( 0 );
}
res = tolower( res );
if(res && !ContainsString( res, "such user" ) && !ContainsString( res, "doesn't exist" ) && !ContainsString( res, "???" ) && !ContainsString( res, "invalid" ) && !ContainsString( res, "forward" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

