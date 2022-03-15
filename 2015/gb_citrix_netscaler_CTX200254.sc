CPE = "cpe:/a:citrix:netscaler";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105275" );
	script_bugtraq_id( 71350 );
	script_cve_id( "CVE-2014-8580" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_version( "2021-04-22T08:55:01+0000" );
	script_name( "Citrix NetScaler Unauthorised Access Vulnerability (CTX200254)" );
	script_xref( name: "URL", value: "https://support.citrix.com/article/CTX200254" );
	script_tag( name: "impact", value: "An authentication flaw has been identified in certain configurations of Citrix NetScaler ADC and
NetScaler Gateway that could allow an authenticated user to obtain unauthorised access to network resources for another authenticated
user." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to
Citrix NetScaler ADC and NetScaler Gateway 10.5-52.11 or later.
Citrix NetScaler ADC and NetScaler Gateway 10.1-129.11 or later.
Citrix NetScaler 10.1-129.1105.e or later." );
	script_tag( name: "summary", value: "The remote Citrix Netscaler is prone to an unauthorised access
vulnerability." );
	script_tag( name: "affected", value: "Citrix NetScaler
Version 10.5.x between 10.5.50.10 and 10.5.51.10
Version 10.1.x between 10.1.122.17 and 10.1.128.8
Version 10.1.x 'Enhanced' between 10.1-120.1316.e and 10.1-128.8003.e" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-04-22 08:55:01 +0000 (Thu, 22 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-05-12 13:12:00 +0200 (Tue, 12 May 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_citrix_netscaler_version.sc" );
	script_mandatory_keys( "citrix_netscaler/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(get_kb_item( "citrix_netscaler/enhanced_build" )){
	enhanced = TRUE;
}
if( enhanced ){
	if(version_in_range( version: vers, test_version: "10.1.120.1316", test_version2: "10.1.128.8003" )){
		fix = "10.1 build 129.1105.e";
		vers = vers + ".e";
	}
}
else {
	if(version_in_range( version: vers, test_version: "10.5.50.10", test_version2: "10.5.51.10" )){
		fix = "10.5 build 52.11";
	}
	if(version_in_range( version: vers, test_version: "10.1.122.17", test_version2: "10.1.128.8" )){
		fix = "10.1 build 129.11";
	}
}
if(fix){
	report = "Installed version: " + vers + "\n" + "Fixed version:     " + fix + "\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

