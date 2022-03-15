CPE = "cpe:/a:solarwinds:log_and_event_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106747" );
	script_version( "2021-09-14T10:02:44+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 10:02:44 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-12 16:22:13 +0200 (Wed, 12 Apr 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-04-21 17:36:00 +0000 (Fri, 21 Apr 2017)" );
	script_cve_id( "CVE-2017-7646", "CVE-2017-7647", "CVE-2017-7722" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "SolarWinds Log and Event Manager Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_solarwinds_log_event_manager_version.sc" );
	script_mandatory_keys( "solarwinds_lem/version" );
	script_tag( name: "summary", value: "SolarWinds LEM is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "SolarWinds LEM is prone to multiple vulnerabilities:

  - CMC command injection - allows an attacker to inject commands to escape the restricted shell (CVE-2017-7722).

  - Arbitrary command injection - allows an authenticated user to execute arbitrary commands from the CMC
restricted shell (CVE-2017-7647).

  - Access Control - allows an authenticated used to browse the LEM servers filesystem and read contents of
arbitrary files (CVE-2017-7646).

  - Postgres Database Service - allows hardcoded credentials access to the Postgres database service via IPv6.

  - Arbitrary File Read - allows an attacker to edit the SSH logon banner & read arbitrary files.

  - Privilege Escalation - allows an attacker to run certain commands as a privileged user." );
	script_tag( name: "affected", value: "SolarWinds Log and Event Manager version 6.3.1 and prior." );
	script_tag( name: "solution", value: "Upgrade to version 6.3.1 Hotfix 4 or later." );
	script_xref( name: "URL", value: "https://thwack.solarwinds.com/thread/111223" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "6.3.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.3.1 Hotfix 4" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "6.3.1" )){
	hotfix = get_kb_item( "solarwinds_lem/hotfix" );
	if(!hotfix || int( hotfix ) < 4){
		report = report_fixed_ver( installed_version: version, installed_patch: hotfix, fixed_version: "6.3.1", fixed_patch: "4" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

