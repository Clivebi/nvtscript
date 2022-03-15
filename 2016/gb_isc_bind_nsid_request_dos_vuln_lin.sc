CPE = "cpe:/a:isc:bind";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809461" );
	script_version( "2021-03-26T13:22:13+0000" );
	script_cve_id( "CVE-2016-2848" );
	script_bugtraq_id( 93814 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-03-26 13:22:13 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-10-24 18:23:32 +0530 (Mon, 24 Oct 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "ISC BIND NSID Request Denial of Service Vulnerability - Linux" );
	script_tag( name: "summary", value: "ISC BIND is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to mishandling of
  packets with malformed options. A remote attacker could use this flaw to make
  named exit unexpectedly with an assertion failure via a specially crafted DNS
  packet." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service." );
	script_tag( name: "affected", value: "ISC BIND versions 9.1.0 through 9.8.4-P2
  and 9.9.0 through 9.9.2-P2." );
	script_tag( name: "solution", value: "Update to ISC BIND version 9.9.9-P3 or
  9.10.4-P3 or 9.11.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://kb.isc.org/docs/aa-01433" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_isc_bind_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "isc/bind/detected", "Host/runs_unixoide" );
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
if(version_in_range( version: version, test_version: "9.1.0", test_version2: "9.8.4p2" ) || version_in_range( version: version, test_version: "9.9.0", test_version2: "9.9.2p2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.9.9-P3 or 9.10.4-P3 or 9.11.0", install_path: location );
	security_message( data: report, port: port, proto: proto );
	exit( 0 );
}
exit( 99 );

