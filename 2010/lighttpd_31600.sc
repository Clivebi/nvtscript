CPE = "cpe:/a:lighttpd:lighttpd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100449" );
	script_version( "$Revision: 12637 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-04 09:36:44 +0100 (Tue, 04 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2010-01-14 12:06:50 +0100 (Thu, 14 Jan 2010)" );
	script_bugtraq_id( 31600 );
	script_cve_id( "CVE-2008-4360", "CVE-2008-4359" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Lighttpd < 1.4.20 Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/31600" );
	script_xref( name: "URL", value: "http://www.lighttpd.net/" );
	script_xref( name: "URL", value: "http://www.lighttpd.net/security/lighttpd_sa_2008_05.txt" );
	script_xref( name: "URL", value: "http://www.lighttpd.net/security/lighttpd_sa_2008_06.txt" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "sw_lighttpd_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "lighttpd/installed" );
	script_tag( name: "solution", value: "The vendor has released lighttpd 1.4.20 to address this issue. Please
 see the references for more information." );
	script_tag( name: "summary", value: "The 'lighttpd' web server is prone to multiple security vulnerabilities." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to bypass certain security
 restrictions and obtain sensitive information. This may lead to other attacks." );
	script_tag( name: "affected", value: "Versions prior to 'lighttpd' 1.4.20 are vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "1.4.20" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.4.20" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

