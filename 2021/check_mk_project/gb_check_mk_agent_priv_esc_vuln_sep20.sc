CPE = "cpe:/a:check_mk_project:check_mk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146389" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-28 09:16:16 +0000 (Wed, 28 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-25 13:49:00 +0000 (Thu, 25 Feb 2021)" );
	script_cve_id( "CVE-2020-24908" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Check MK Agent < 1.6.0p17 Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "gb_check_mk_agent_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "check_mk/agent/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "Check MK Agent is prone to a privilege escalation vulnerability
  on Windows." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Check MK Agent allows local users to obtain SYSTEM privileges
  via a Trojan horse shell script in the %PROGRAMDATA%\\checkmk\\agent\\local directory." );
	script_tag( name: "affected", value: "Check MK Agent version 1.6.0p16 and prior on Windows." );
	script_tag( name: "solution", value: "Update to version 1.6.0p17 or later." );
	script_xref( name: "URL", value: "https://checkmk.com/werk/11460" );
	script_xref( name: "URL", value: "https://www.compass-security.com/fileadmin/Research/Advisories/2020-05_CSNC-2020-005_Checkmk_Local_Privilege_Escalation.txt" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "check_mk_agent" )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.6.0p17" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.6.0p17" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

