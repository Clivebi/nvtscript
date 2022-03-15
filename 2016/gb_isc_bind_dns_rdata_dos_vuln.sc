CPE = "cpe:/a:isc:bind";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807203" );
	script_version( "2021-03-26T13:22:13+0000" );
	script_cve_id( "CVE-2012-5166" );
	script_bugtraq_id( 55852 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-03-26 13:22:13 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-01-28 12:39:11 +0530 (Thu, 28 Jan 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "ISC BIND DNS RDATA Handling Remote Denial of Service Vulnerability (Jan 2016" );
	script_tag( name: "summary", value: "ISC BIND is prone to a remote denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in the DNS
  RDATA Handling in ISC BIND." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to cause denial of service." );
	script_tag( name: "affected", value: "ISC BIND versions 9.2.x through 9.6.x,
  9.4-ESV through 9.4-ESV-R5-P1, 9.6-ESV through 9.6-ESV-R7-P3, 9.7.0 through
  9.7.6-P3, 9.8.0 through 9.8.3-P3, 9.9.0 through 9.9.1-P3." );
	script_tag( name: "solution", value: "Update to ISC BIND version 9.7.7 or 9.7.6-P4
  or 9.6-ESV-R8 or 9.6-ESV-R7-P4 or 9.8.4 or 9.8.3-P4 or 9.9.2 or 9.9.1-P4 later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://kb.isc.org/docs/aa-00801" );
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
if( version_in_range( version: version, test_version: "9.2", test_version2: "9.6" ) ){
	fix = "9.7.7";
	VULN = TRUE;
}
else {
	if( version_in_range( version: version, test_version: "9.4", test_version2: "9.4r5_p1" ) ){
		fix = "9.6-ESV-R8";
		VULN = TRUE;
	}
	else {
		if( version_in_range( version: version, test_version: "9.7.0", test_version2: "9.7.6p3" ) ){
			fix = "9.7.6-P4";
			VULN = TRUE;
		}
		else {
			if( version_in_range( version: version, test_version: "9.8.0", test_version2: "9.8.3p3" ) ){
				fix = "9.8.3-P4";
				VULN = TRUE;
			}
			else {
				if( version_in_range( version: version, test_version: "9.6", test_version2: "9.6R7_P3" ) ){
					fix = "9.6-ESV-R7-P4";
					VULN = TRUE;
				}
				else {
					if(version_in_range( version: version, test_version: "9.9.0", test_version2: "9.9.1p3" )){
						fix = "9.9.1-P4";
						VULN = TRUE;
					}
				}
			}
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
	security_message( data: report, port: port, proto: proto );
	exit( 0 );
}
exit( 99 );

