CPE = "cpe:/a:isc:bind";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806998" );
	script_version( "2021-03-26T13:22:13+0000" );
	script_cve_id( "CVE-2015-8461" );
	script_bugtraq_id( 79347 );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-03-26 13:22:13 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-01-27 15:07:28 +0530 (Wed, 27 Jan 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "ISC BIND Denial of Service Vulnerability (CVE-2015-8461)" );
	script_tag( name: "summary", value: "ISC BIND is prone to a remote denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a race condition
  in the 'resolver.c' file when handling socket errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service." );
	script_tag( name: "affected", value: "ISC BIND versions 9.9.8 through 9.9.8-P1,
  9.9.8-S1 through 9.9.8-S2, 9.10.3 through 9.10.3-P1." );
	script_tag( name: "solution", value: "Update to ISC BIND version 9.9.8-P2 or
  9.9.8-S3 or 9.10.3-P2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://kb.isc.org/docs/aa-01319" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_isc_bind_consolidation.sc" );
	script_mandatory_keys( "isc/bind/detected" );
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
if( version_in_range( version: version, test_version: "9.9.8", test_version2: "9.9.8p1" ) ){
	fix = "9.9.8-P2";
	VULN = TRUE;
}
else {
	if( version_in_range( version: version, test_version: "9.9.8s1", test_version2: "9.9.8s2" ) ){
		fix = "9.9.8-S3";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: version, test_version: "9.10.3", test_version2: "9.10.3p1" )){
			fix = "9.10.3-P2";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
	security_message( data: report, port: port, proto: proto );
	exit( 0 );
}
exit( 99 );

