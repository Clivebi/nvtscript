CPE = "cpe:/a:unbound:unbound";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100416" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-01-04 18:09:12 +0100 (Mon, 04 Jan 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 37459 );
	script_cve_id( "CVE-2009-3602" );
	script_name( "Unbound DNS Server NSEC3 Signature Verification DNS Spoofing Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "unbound_version.sc" );
	script_mandatory_keys( "unbound/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37459" );
	script_xref( name: "URL", value: "http://unbound.net/pipermail/unbound-users/2009-October/000852.html" );
	script_xref( name: "URL", value: "http://unbound.net/index.html" );
	script_tag( name: "impact", value: "Successful exploits allow remote attackers to spoof delegation
  responses so as to downgrade secure delegations to insecure status,
  which may aid in further attacks." );
	script_tag( name: "affected", value: "Versions prior to Unbound 1.3.4 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "Unbound DNS Server is prone to a DNS-spoofing vulnerability." );
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
if(version_is_less( version: version, test_version: "1.3.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.4" );
	security_message( data: report, port: port, proto: proto );
	exit( 0 );
}
exit( 99 );

