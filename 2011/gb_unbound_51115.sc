CPE = "cpe:/a:unbound:unbound";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103370" );
	script_bugtraq_id( 51115 );
	script_cve_id( "CVE-2011-4528", "CVE-2011-4869" );
	script_version( "$Revision: 11997 $" );
	script_name( "Unbound Multiple Denial of Service Vulnerabilities" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-12-20 11:19:55 +0100 (Tue, 20 Dec 2011)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "This script is Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "unbound_version.sc" );
	script_mandatory_keys( "unbound/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47220" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/209659" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51115" );
	script_xref( name: "URL", value: "http://unbound.nlnetlabs.nl/downloads/CVE-2011-4528.txt" );
	script_xref( name: "URL", value: "http://unbound.net/index.html" );
	script_tag( name: "impact", value: "An attacker can exploit these issues to cause the affected application
  to crash, denying service to legitimate users." );
	script_tag( name: "affected", value: "Versions prior to Unbound 1.4.14 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more details." );
	script_tag( name: "summary", value: "Unbound is prone to multiple remote denial-of-service vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_proto( cpe: CPE, port: port )){
	exit( 0 );
}
version = infos["version"];
proto = infos["proto"];
if(version_is_less( version: version, test_version: "1.4.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.4.14" );
	security_message( data: report, port: port, proto: proto );
	exit( 0 );
}
exit( 99 );

