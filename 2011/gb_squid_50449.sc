CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103320" );
	script_cve_id( "CVE-2011-4096" );
	script_bugtraq_id( 50449 );
	script_version( "2019-07-05T10:41:31+0000" );
	script_name( "Squid Proxy Caching Server CNAME Denial of Service Vulnerability" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2019-07-05 10:41:31 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2011-11-01 08:00:00 +0100 (Tue, 01 Nov 2011)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "This script is Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_require_ports( "Services/http_proxy", 3128, "Services/www", 8080 );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50449" );
	script_xref( name: "URL", value: "http://bugs.squid-cache.org/show_bug.cgi?id=3237" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=750316" );
	script_xref( name: "URL", value: "http://permalink.gmane.org/gmane.comp.security.oss.general/6144" );
	script_tag( name: "summary", value: "Squid proxy caching server is prone to a denial-of-service
  vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to cause an affected application to
  crash, denying service to legitimate users." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
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
if(version_is_equal( version: vers, test_version: "3.1.16" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.1.17" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

