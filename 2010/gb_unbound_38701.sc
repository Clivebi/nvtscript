CPE = "cpe:/a:unbound:unbound";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100531" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-03-15 13:03:19 +0100 (Mon, 15 Mar 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-0969" );
	script_bugtraq_id( 38701 );
	script_name( "Unbound 'sock_list' Structure Allocation Remote Denial Of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "unbound_version.sc" );
	script_mandatory_keys( "unbound/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38701" );
	script_xref( name: "URL", value: "http://www.unbound.net/pipermail/unbound-users/2010-March/001057.html" );
	script_xref( name: "URL", value: "http://unbound.net/index.html" );
	script_tag( name: "impact", value: "Successful exploits may allow an attacker to crash the affected
  application, resulting in a denial-of-service condition. Given the
  nature of this issue, attackers may also be able to run arbitrary
  code, but this has not been confirmed." );
	script_tag( name: "affected", value: "Versions prior to Unbound 1.4.3 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "Unbound is prone to a remote denial-of-service vulnerability." );
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
if(version_is_less( version: version, test_version: "1.4.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.4.3" );
	security_message( data: report, port: port, proto: proto );
	exit( 0 );
}
exit( 99 );

