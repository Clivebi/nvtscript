CPE = "cpe:/a:isc:bind";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100717" );
	script_version( "2021-03-26T13:22:13+0000" );
	script_tag( name: "last_modification", value: "2021-03-26 13:22:13 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2010-07-16 12:38:11 +0200 (Fri, 16 Jul 2010)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:N/A:P" );
	script_bugtraq_id( 41730 );
	script_cve_id( "CVE-2010-0213" );
	script_name( "ISC BIND 'RRSIG' Record Type Remote DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_isc_bind_consolidation.sc" );
	script_mandatory_keys( "isc/bind/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/41730" );
	script_xref( name: "URL", value: "https://www.isc.org/software/bind/advisories/cve-2010-0213" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "ISC BIND is prone to a remote denial-of-service vulnerability." );
	script_tag( name: "insight", value: "The flaw exists because the software fails to handle certain record types." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to cause the application to fall
  into an infinite loop, denying service to legitimate users." );
	script_tag( name: "affected", value: "ISC BIND versions 9.7.1 and 9.7.1-P1 are vulnerable." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_full( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
proto = infos["proto"];
location = infos["location"];
if(version_is_equal( version: version, test_version: "9.7.1" ) || version_is_equal( version: version, test_version: "9.7.1p1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory", install_path: location );
	security_message( data: report, port: port, proto: proto );
	exit( 0 );
}
exit( 99 );

