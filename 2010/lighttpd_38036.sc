CPE = "cpe:/a:lighttpd:lighttpd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100480" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-02-02 21:07:02 +0100 (Tue, 02 Feb 2010)" );
	script_bugtraq_id( 38036 );
	script_cve_id( "CVE-2010-0295" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "lighttpd Slow Request Handling Remote Denial Of Service Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38036" );
	script_xref( name: "URL", value: "http://www.lighttpd.net/" );
	script_xref( name: "URL", value: "http://redmine.lighttpd.net/issues/2147" );
	script_xref( name: "URL", value: "http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2010_01.txt" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "sw_lighttpd_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "lighttpd/installed" );
	script_tag( name: "solution", value: "SVN fixes and patches are available. Please see the references
 for details." );
	script_tag( name: "summary", value: "lighttpd is prone to a denial-of-service vulnerability." );
	script_tag( name: "impact", value: "Remote attackers can exploit this issue to cause the application to
 hang, denying service to legitimate users." );
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
if(version_is_less_equal( version: vers, test_version: "1.4.25" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.4.25" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

