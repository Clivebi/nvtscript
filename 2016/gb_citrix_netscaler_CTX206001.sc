CPE = "cpe:/a:citrix:netscaler";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105538" );
	script_cve_id( "CVE-2016-2071", "CVE-2016-2072" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-09-20T09:01:50+0000" );
	script_name( "Citrix NetScaler Application Delivery Controller and NetScaler Gateway Multiple Security Updates (CTX206001)" );
	script_xref( name: "URL", value: "http://support.citrix.com/article/CTX206001" );
	script_tag( name: "insight", value: "The following vulnerabilities have been addressed:

  - CVE-2016-2071: Citrix NetScaler Application Delivery Controller and NetScaler Gateway Command Privilege Elevation Vulnerability Through Un-sanitised NS Web GUI Commands.

  - CVE-2016-2071: Citrix NetScaler Application Delivery Controller and NetScaler Gateway Command Privilege Elevation Vulnerability Through Un-sanitised NS Web GUI Commands." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Updates are available" );
	script_tag( name: "summary", value: "A number of vulnerabilities have been identified in Citrix NetScaler Application Delivery Controller (ADC) and NetScaler Gateway that could allow a malicious, unprivileged user to perform privileged operations or execute commands." );
	script_tag( name: "affected", value: "Version 11.0 earlier than 11.0 Build 64.34. Version 10.5 earlier than 10.5 Build 59.13 and 10.5.e earlier than 10.5.e Build 59.1305.e. All builds of version 10.1 are affected by CVE-2016-2072 only. CVE-2016-2071 does not affect version 10.1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-09-20 09:01:50 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-03 03:24:00 +0000 (Sat, 03 Dec 2016)" );
	script_tag( name: "creation_date", value: "2016-02-11 17:00:25 +0100 (Thu, 11 Feb 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(version_in_range( version: vers, test_version: "10.5", test_version2: "10.5.59.1304" )){
		fix = "10.5.e Build 59.1305.e";
		vers = vers + ".e";
	}
}
else {
	if(version_in_range( version: vers, test_version: "10.5", test_version2: "10.5.59.12" )){
		fix = "10.5 Build 59.13";
	}
	if(version_in_range( version: vers, test_version: "10.1", test_version2: "10.1.133.8" )){
		fix = "10.1 build 133.9";
	}
	if(version_in_range( version: vers, test_version: "11.0", test_version2: "11.0.64.33" )){
		fix = "11.0 Build  64.34";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );
