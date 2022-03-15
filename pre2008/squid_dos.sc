CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10768" );
	script_version( "2019-07-05T10:41:31+0000" );
	script_tag( name: "last_modification", value: "2019-07-05 10:41:31 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3354 );
	script_cve_id( "CVE-2001-0843" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Squid Denial-of-Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "This script is Copyright (C) 2001 Adam Baldwin" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_require_ports( "Services/http_proxy", 3128, "Services/www", 8080 );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_tag( name: "summary", value: "A problem exists in the way the remote Squid proxy server handles a
  special 'mkdir-only' PUT request, and causes denial of service to the proxy server." );
	script_tag( name: "impact", value: "An attacker may use this flaw to prevent your LAN users from accessing
  the web." );
	script_tag( name: "solution", value: "Apply the vendor released patch, for squid it is available at the
  linked references. You can also protect yourself by enabling access lists on your proxy." );
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
if(ContainsString( vers, "2.3" ) && ( ContainsString( vers, "STABLE1" ) || ContainsString( vers, "STABLE3" ) || ContainsString( vers, "STABLE4" ) || ContainsString( vers, "STABLE5" ) )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(ContainsString( vers, "2.4" ) && ( ContainsString( vers, "STABLE1" ) || ContainsString( vers, "PRE-STABLE2" ) || ContainsString( vers, "PRE-STABLE" ) || ContainsString( vers, "DEVEL4" ) || ContainsString( vers, "DEVEL2" ) )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

