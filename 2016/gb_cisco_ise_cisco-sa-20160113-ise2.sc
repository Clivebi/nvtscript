CPE = "cpe:/a:cisco:identity_services_engine";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105524" );
	script_cve_id( "CVE-2015-6317" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:C/A:N" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_name( "Cisco Identity Services Engine Unauthorized Access Vulnerability " );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160113-ise2" );
	script_tag( name: "impact", value: "An attacker could exploit this vulnerability by authenticating at a low-privileged account and then accessing the web resources directly. An exploit could allow the attacker to access web pages that are reserved for higher-privileged administrative users." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability occurs because specific types of web resources are not correctly filtered for administrative users with different privileges." );
	script_tag( name: "solution", value: "Cisco has released software updates that address these vulnerabilities." );
	script_tag( name: "summary", value: "Cisco Identity Services Engine versions prior to 2.0 contain a vulnerability that could allow a low-privileged authenticated, remote attacker to access specific web resources that are designed to be accessed only by higher-privileged administrative users." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-07 18:19:00 +0000 (Wed, 07 Dec 2016)" );
	script_tag( name: "creation_date", value: "2016-01-20 12:43:15 +0100 (Wed, 20 Jan 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ise_version.sc" );
	script_mandatory_keys( "cisco_ise/version", "cisco_ise/patch" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(!patch = get_kb_item( "cisco_ise/patch" )){
	exit( 0 );
}
v = split( buffer: version, sep: ".", keep: FALSE );
version = v[0] + "." + v[1] + "." + v[2];
if(version_is_less( version: version, test_version: "2.0" )){
	fix = "2.0";
	if(version == "1.4.0"){
		if( int( patch ) < 5 ) {
			fix = "1.4 Patch 5";
		}
		else {
			exit( 99 );
		}
	}
}
if(fix){
	report = "Installed version: " + version + "\n";
	if(int( patch ) > 0){
		report += "Installed patch:   " + patch + "\n";
	}
	report += "Fixed version:     " + fix;
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

