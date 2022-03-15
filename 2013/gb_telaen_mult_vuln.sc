if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803646" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-2621", "CVE-2013-2623", "CVE-2013-2624" );
	script_bugtraq_id( 60290, 60288, 60340 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-04 17:02:00 +0000 (Tue, 04 Feb 2020)" );
	script_tag( name: "creation_date", value: "2013-06-10 16:45:05 +0530 (Mon, 10 Jun 2013)" );
	script_name( "Telaen Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2013/Jun/12" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/telaen-130-xss-open-redirection-disclosure" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to perform open redirection,
  obtain sensitive information and execute arbitrary code in a user's browser
  session in context of an affected site." );
	script_tag( name: "affected", value: "Telaen version 1.3.0 and prior" );
	script_tag( name: "insight", value: "The flaws are due to:

  - Improper validation of input passed to 'f_email' parameter upon submission
    to the '/telaen/index.php' script.

  - Improper validation of user-supplied input upon submission to the
    '/telaen/redir.php' script.

  - Issue when requested for the '/telaen/inc/init.php' script." );
	script_tag( name: "solution", value: "Upgrade to Telaen version 1.3.1 or later." );
	script_tag( name: "summary", value: "This host is running Telaen and is prone to multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.telaen.com" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
Port = http_get_port( default: 80 );
if(!http_can_host_php( port: Port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/telaen", "/webmail", http_cgi_dirs( port: Port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/index.php" ), port: Port );
	if(ContainsString( res, ">Powered by Telaen" ) && ContainsString( res, "login" )){
		host = http_host_name( port: Port );
		req = http_get( item: NASLString( dir, "/redir.php?http://", host, "/telaen/index.php" ), port: Port );
		res = http_keepalive_send_recv( port: Port, data: req, bodyonly: FALSE );
		if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
			matched = eregmatch( string: res, pattern: ">http://[0-9.]+(.*)</a>" );
			if(matched[1]){
				url = dir + matched[1];
				req = http_get( item: url, port: Port );
				res = http_keepalive_send_recv( port: Port, data: req );
				if(ContainsString( res, ">Powered by Telaen" ) && ContainsString( res, "login" )){
					security_message( port: Port );
					exit( 0 );
				}
			}
		}
	}
}
exit( 99 );

