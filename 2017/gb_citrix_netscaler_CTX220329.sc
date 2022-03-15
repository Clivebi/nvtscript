CPE = "cpe:/a:citrix:netscaler";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140153" );
	script_cve_id( "CVE-2017-5933" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_version( "2021-09-09T11:01:33+0000" );
	script_name( "Vulnerability in Citrix NetScaler Application Delivery Controller and Citrix NetScaler Gateway GCM Nonce Generation" );
	script_xref( name: "URL", value: "https://support.citrix.com/article/CTX220329" );
	script_xref( name: "URL", value: "https://github.com/nonce-disrespect/nonce-disrespect" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "summary", value: "A flaw has been identified in the GCM nonce generation functionality of Citrix NetScaler application
  Delivery Controller (ADC) and Citrix NetScaler Gateway that could result in the interception of session data." );
	script_tag( name: "affected", value: "Version 11.1 earlier than 11.1 Build 51.21

  Version 11.0 earlier than 11.0 Build 69.12/69.123

  Version 10.5 earlier than 10.5 Build 65.11" );
	script_tag( name: "solution", value: "Updates are available. This vulnerability has been addressed in the following versions of Citrix NetScaler ADC and NetScaler Gateway:

  Citrix NetScaler ADC and NetScaler Gateway version 11.1 Build 51.21 and later

  Citrix NetScaler ADC and NetScaler Gateway version 11.0 Build 69.12/69.123 and later

  Citrix NetScaler ADC and NetScaler Gateway version 10.5 Build 65.11 and later" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-09-09 11:01:33 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-03-14 19:27:00 +0000 (Tue, 14 Mar 2017)" );
	script_tag( name: "creation_date", value: "2017-02-08 12:46:21 +0100 (Wed, 08 Feb 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if( enhanced ) {
	exit( 99 );
}
else {
	if(version_in_range( version: vers, test_version: "10.5", test_version2: "10.5.65.10" )){
		fix = "10.5 Build 65.11";
	}
	if(version_in_range( version: vers, test_version: "11.0", test_version2: "11.0.69.11" )){
		fix = "11.0 Build 69.12";
	}
	if(version_in_range( version: vers, test_version: "11.1", test_version2: "11.1.51.20" )){
		fix = "11.1 Build 51.21";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

