CPE = "cpe:/a:oracle:weblogic_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10698" );
	script_version( "2021-05-10T09:07:58+0000" );
	script_tag( name: "last_modification", value: "2021-05-10 09:07:58 +0000 (Mon, 10 May 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 2513 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "WebLogic Server /%00/ bug" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2001 StrongHoldNet" );
	script_family( "Web Servers" );
	script_dependencies( "gb_oracle_weblogic_consolidation.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "oracle/weblogic/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/2513" );
	script_tag( name: "solution", value: "Upgrade to WebLogic 6.0 with Service Pack 1." );
	script_tag( name: "summary", value: "Requesting a URL with '%00', '%2e', '%2f' or '%5c' appended to it
  makes some WebLogic servers dump the listing of the page directory, thus showing potentially sensitive files." );
	script_tag( name: "impact", value: "An attacker may also use this flaw to view
  the source code of JSP files, or other dynamic content." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_probe" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
func http_getdirlist( itemstr, port ){
	buffer = http_get( item: itemstr, port: port );
	rbuf = http_keepalive_send_recv( port: port, data: buffer );
	if(!rbuf){
		return;
	}
	data = tolower( rbuf );
	if(( ContainsString( data, "directory listing of" ) ) || ( ContainsString( data, "index of" ) )){
		if( strlen( itemstr ) > 1 ){
			report = http_report_vuln_url( port: port, url: itemstr );
			security_message( port: port, data: report );
		}
		else {
			if(strlen( itemstr ) == 1){
				exit( 0 );
			}
		}
	}
}
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
http_getdirlist( itemstr: "/", port: port );
http_getdirlist( itemstr: "/%2e/", port: port );
http_getdirlist( itemstr: "/%2f/", port: port );
http_getdirlist( itemstr: "/%5c/", port: port );
http_getdirlist( itemstr: "/%00/", port: port );

