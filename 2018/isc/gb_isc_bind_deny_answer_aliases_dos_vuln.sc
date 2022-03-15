CPE = "cpe:/a:isc:bind";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813750" );
	script_version( "2021-05-28T06:00:18+0200" );
	script_cve_id( "CVE-2018-5740" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-05-28 06:00:18 +0200 (Fri, 28 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-08-10 12:14:44 +0530 (Fri, 10 Aug 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "ISC BIND 'deny-answer-aliases' Denial of Service Vulnerability" );
	script_tag( name: "summary", value: "ISC BIND is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a defect in the
  feature 'deny-answer-aliases' which leads to assertion failure in 'name.c'." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service (assertion failure)." );
	script_tag( name: "affected", value: "ISC BIND versions 9.7.0 through 9.8.8,
  9.9.0 through 9.9.13, 9.10.0 through 9.10.8, 9.11.0 through 9.11.4,
  9.12.0 through 9.12.2 and 9.13.0 through 9.13.2." );
	script_tag( name: "solution", value: "Update to ISC BIND version 9.9.13-P1 or
  9.10.8-P1 or 9.11.4-P1 or 9.12.2-P1 or 9.11.3-S3 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://kb.isc.org/docs/aa-01639" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(!IsMatchRegexp( version, "^9\\." )){
	exit( 0 );
}
if( IsMatchRegexp( version, "^9\\.11\\.[0-9]s[0-9]" ) ){
	if(version_in_range( version: version, test_version: "9.11.0s0", test_version2: "9.11.3s2" )){
		fix = "9.11.3-S3";
	}
}
else {
	if( version_in_range( version: version, test_version: "9.7.0", test_version2: "9.8.8" ) || version_in_range( version: version, test_version: "9.9.0", test_version2: "9.9.13" ) ){
		fix = "9.9.13-P1";
	}
	else {
		if( version_in_range( version: version, test_version: "9.10.0", test_version2: "9.10.8" ) ){
			fix = "9.10.8-P1";
		}
		else {
			if( version_in_range( version: version, test_version: "9.11.0", test_version2: "9.11.4" ) ){
				fix = "9.11.4-P1";
			}
			else {
				if( version_in_range( version: version, test_version: "9.12.0", test_version2: "9.12.2" ) ){
					fix = "9.12.2-P1";
				}
				else {
					if(version_in_range( version: version, test_version: "9.13.0", test_version2: "9.13.2" )){
						fix = "9.14";
					}
				}
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
	security_message( port: port, data: report, proto: proto );
	exit( 0 );
}
exit( 99 );

