CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15463" );
	script_version( "$Revision: 13975 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 11385 );
	script_cve_id( "CVE-2004-0918" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Squid remote denial of service" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_require_ports( "Services/http_proxy", 3128, "Services/www", 8080 );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_tag( name: "summary", value: "The remote squid caching proxy, according to its version number, may be
  vulnerable to a remote denial of service." );
	script_tag( name: "insight", value: "This flaw is due to an input validation error in the SNMP module." );
	script_tag( name: "impact", value: "An attacker can exploit this flaw to crash the server with a specially
  crafted UDP packet." );
	script_tag( name: "solution", value: "Upgrade to squid 2.5.STABLE7 or newer" );
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
if(version_in_range( version: vers, test_version: "2.0", test_version2: "2.5.STABLE6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.5.STABLE7" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

