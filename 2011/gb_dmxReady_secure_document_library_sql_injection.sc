if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801952" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-07-07 15:43:33 +0200 (Thu, 07 Jul 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "DmxReady Secure Document Library SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/102842/dmxreadysdl12-sql.txt" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause SQL
  Injection attack and gain sensitive information." );
	script_tag( name: "affected", value: "DmxReady Secure Document Library version 1.2" );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input
  via the 'ItemID' parameter in 'update.asp' that allows attacker to manipulate SQL
  queries by injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running DmxReady Secure Document Library and is prone
  to SQL injection vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
for dir in nasl_make_list_unique( "/SecureDocumentLibrary", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: dir + "/inc_securedocumentlibrary.asp", port: port );
	rcvRes = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( rcvRes, "<title>Secure Document Library</title>" )){
		url = dir + "/admin/SecureDocumentLibrary/DocumentLibraryManager/update.asp?ItemID='1";
		req2 = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n\\r\\n" );
		rcvRes = http_keepalive_send_recv( port: port, data: req2 );
		if(ContainsString( rcvRes, "error '80040e14" ) && ContainsString( rcvRes, ">Syntax error" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

