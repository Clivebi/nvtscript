CPE = "cpe:/a:eterna:bozohttpd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100750" );
	script_version( "$Revision: 14165 $" );
	script_bugtraq_id( 42021 );
	script_cve_id( "CVE-2010-2195", "CVE-2010-2320" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 07:59:37 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-08-09 13:36:05 +0200 (Mon, 09 Aug 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "bozohttpd Security Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_bozotic_http_server_detect.sc" );
	script_mandatory_keys( "bozohttpd/detected" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/42021" );
	script_xref( name: "URL", value: "https://bugs.launchpad.net/ubuntu/+source/bozohttpd/+bug/582473" );
	script_xref( name: "URL", value: "http://www.eterna.com.au/bozohttpd/" );
	script_tag( name: "impact", value: "An attacker can exploit this issue to bypass certain security
  restrictions and gain access to restricted content. This can lead to other attacks." );
	script_tag( name: "affected", value: "bozohttpd 20090522 and 20100509 are vulnerable. Other versions may
  also be affected." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "bozohttpd is prone to a security-bypass vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( port: port, cpe: CPE )){
	exit( 0 );
}
if(version_is_equal( version: vers, test_version: "20090522" ) || version_is_equal( version: vers, test_version: "20100509" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

