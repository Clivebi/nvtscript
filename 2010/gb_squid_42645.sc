CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100774" );
	script_version( "2019-07-05T10:41:31+0000" );
	script_tag( name: "last_modification", value: "2019-07-05 10:41:31 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2010-09-02 16:10:00 +0200 (Thu, 02 Sep 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-2951" );
	script_bugtraq_id( 42645 );
	script_name( "Squid 'DNS' Reply Remote Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_require_ports( "Services/http_proxy", 3128, "Services/www", 8080 );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/42645" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=62692" );
	script_xref( name: "URL", value: "http://marc.info/?l=squid-users&m=128263555724981&w=2" );
	script_tag( name: "affected", value: "Squid 3.1.6 is vulnerable. Other versions may also be affected." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to execute arbitrary code within
  the context of the affected application. Failed exploit attempts will result in a denial-of-service condition." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "Squid is prone to a remote buffer-overflow vulnerability because it
  fails to perform adequate boundary checks on user-supplied data." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_equal( version: vers, test_version: "3.1.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.1.7" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

