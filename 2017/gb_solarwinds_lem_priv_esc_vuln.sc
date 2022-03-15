CPE = "cpe:/a:solarwinds:log_and_event_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106698" );
	script_version( "2021-09-10T11:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-28 11:42:33 +0700 (Tue, 28 Mar 2017)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2017-5198", "CVE-2017-5199" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "SolarWinds Log and Event Manager SSH Jailbreak and Privilege Escalation Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_solarwinds_log_event_manager_version.sc" );
	script_mandatory_keys( "solarwinds_lem/version" );
	script_tag( name: "summary", value: "SolarWinds LEM is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "SolarWinds LEM is prone to multiple vulnerabilities:

  - Incorrect permissions on management scripts allows privilege escalation. (CVE-2017-5198)

  - Authenticated custom shell Jailbreak and command execution (CVE-2017-5199)" );
	script_tag( name: "affected", value: "SolarWinds Log and Event Manager version 6.3.1 and prior." );
	script_tag( name: "solution", value: "Upgrade to version 6.3.1 Hotfix 3 or later." );
	script_xref( name: "URL", value: "http://blog.0xlabs.com/2017/03/solarwinds-lem-ssh-jailbreak-and.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "6.3.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.3.1 Hotfix 3" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "6.3.1" )){
	hotfix = get_kb_item( "solarwinds_lem/hotfix" );
	if(!hotfix || int( hotfix ) < 3){
		report = report_fixed_ver( installed_version: version, installed_patch: hotfix, fixed_version: "6.3.1", fixed_patch: "3" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 0 );

