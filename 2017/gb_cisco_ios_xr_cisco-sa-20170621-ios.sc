CPE = "cpe:/o:cisco:ios_xr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106893" );
	script_cve_id( "CVE-2017-6719" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-09-09T11:01:33+0000" );
	script_name( "Cisco IOS XR Software Local Command Injection Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170621-ios" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the CLI of Cisco IOS XR Software could allow an
authenticated, local attacker to execute arbitrary commands on the host operating system with root privileges." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient input validation. An attacker could
exploit this vulnerability by sending crafted input to a command in a specific group." );
	script_tag( name: "impact", value: "A successful exploit could allow the attacker to execute arbitrary commands
on the affected system with root privileges." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-09 11:01:33 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-07 17:40:00 +0000 (Fri, 07 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-06-22 10:44:19 +0700 (Thu, 22 Jun 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ios_xr_version.sc" );
	script_mandatory_keys( "cisco/ios_xr/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "6.0.2",
	 "6.0.2.01" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

