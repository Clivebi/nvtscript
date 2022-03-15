CPE = "cpe:/a:trendmicro:interscan_messaging_security_virtual_appliance";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107298" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-14 11:00:01 +0100 (Wed, 14 Feb 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:40:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2018-3609" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Trend Micro InterScan Messaging Security Virtual Appliance (IMSVA Management Portal Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_trend_micro_interscan_messaging_security_virtual_appliance_consolidation.sc" );
	script_mandatory_keys( "trend_micro/imsva/detected", "trend_micro/imsva/build" );
	script_tag( name: "summary", value: "The IMSVA management portal is vulnerable to an authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "This vulnerability could allow an unauthenticated user to access sensitive
  information in a particular log file that could be used for authentication bypass." );
	script_tag( name: "solution", value: "Update to version 9.1 Patch 1 CP1682 or version 9.0 CP1653." );
	script_tag( name: "affected", value: "Versions 9.0 and 9.1." );
	script_xref( name: "URL", value: "https://success.trendmicro.com/solution/1119277" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(!build = get_kb_item( "trend_micro/imsva/build" )){
	exit( 0 );
}
if( ( version == "9.1" ) && ( version_is_less( version: build, test_version: "1682" ) ) ){
	report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "9.1", fixed_build: "1682" );
	Vuln = TRUE;
}
else {
	if(( version == "9.0" ) && ( version_is_less( version: build, test_version: "1653" ) )){
		report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "9.0", fixed_build: "1653" );
		Vuln = TRUE;
	}
}
if(Vuln){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

