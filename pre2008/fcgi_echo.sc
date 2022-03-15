if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10838" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "FastCGI samples Cross Site Scripting" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2002 Matt Moore" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "cross_site_scripting.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Always remove sample applications from production servers." );
	script_tag( name: "summary", value: "Two sample CGI's supplied with FastCGI are vulnerable
  to cross-site scripting attacks. FastCGI is an 'open extension to CGI
  that provides high performance without the limitations of server
  specific APIs', and is included in the default installation of the
  'Unbreakable' Oracle9i Application Server. Various other web servers
  support the FastCGI extensions (Zeus, Pi3Web etc)." );
	script_tag( name: "insight", value: "Two sample CGI's are installed with FastCGI, (echo.exe and echo2.exe
  under Windows, echo and echo2 under Unix). Both of these CGI's output
  a list of environment variables and PATH information for various
  applications. They also display any parameters that were provided
  to them. Hence, a cross site scripting attack can be performed via
  a request such as:

  /fcgi-bin/echo2.exe?blah=<SCRIPT>alert(document.domain)</SCRIPT>" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod", value: "50" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if( os_host_runs( "Windows" ) == "yes" ) {
	files = make_list( "echo.exe",
		 "echo2.exe" );
}
else {
	if( os_host_runs( "Linux" ) == "yes" ) {
		files = make_list( "echo",
			 "echo2" );
	}
	else {
		files = make_list( "echo",
			 "echo.exe",
			 "echo2",
			 "echo2.exe" );
	}
}
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
for file in files {
	url = "/fcgi-bin/" + file + "?foo=<SCRIPT>alert(document.domain)</SCRIPT>";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!res){
		continue;
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<SCRIPT>alert(document.domain)</SCRIPT>" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

