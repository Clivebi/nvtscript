CPE = "cpe:/a:oracle:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11226" );
	script_version( "2020-02-03T15:12:40+0000" );
	script_tag( name: "last_modification", value: "2020-02-03 15:12:40 +0000 (Mon, 03 Feb 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3341 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2001-1372" );
	script_name( "Oracle 9iAS default error information disclosure" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Javier Fernandez-Sanguino" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_oracle_app_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "oracle/http_server/detected" );
	script_tag( name: "summary", value: "Oracle 9iAS allows remote attackers to obtain the physical path of a file
  under the server root via a request for a non-existent .JSP file. The default
  error generated leaks the pathname in an error message." );
	script_tag( name: "solution", value: "Ensure that virtual paths of URL is different from the actual directory
  path. Also, do not use the <servletzonepath> directory in
  'ApJServMount <servletzonepath> <servletzone>' to store data or files.

  Upgrading to Oracle 9iAS 1.1.2.0.0 will also fix this issue." );
	script_xref( name: "URL", value: "http://www.nextgenss.com/papers/hpoas.pdf" );
	script_xref( name: "URL", value: "http://otn.oracle.com/deploy/security/pdf/jspexecute_alert.pdf" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/278971" );
	script_xref( name: "URL", value: "http://www.cert.org/advisories/CA-2002-08.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
errorjsp = "/nonexistent.jsp";
req = http_get( item: errorjsp, port: port );
res = http_send_recv( data: req, port: port );
if(!res){
	exit( 0 );
}
location = egrep( pattern: "java.io.FileNotFoundException", string: res );
if(location){
	path = ereg_replace( pattern: strcat( "(java.io.FileNotFoundException: )(.*[^/\\])[/\\]+", substr( errorjsp, 1 ), ".*" ), replace: "\\2", string: location );
	security_message( port: port, data: NASLString( "The web root physical is ", path ) );
	exit( 0 );
}
exit( 99 );

