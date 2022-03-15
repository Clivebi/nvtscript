CPE = "cpe:/a:tenable:nessus_agent";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144902" );
	script_version( "2021-07-13T02:01:14+0000" );
	script_tag( name: "last_modification", value: "2021-07-13 02:01:14 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-11-09 03:09:03 +0000 (Mon, 09 Nov 2020)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-16 18:41:00 +0000 (Mon, 16 Nov 2020)" );
	script_cve_id( "CVE-2020-5793" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Tenable Nessus Agent 8.0.0 - 8.1.0 Arbitrary Code Execution vulnerability (TNS-2020-07)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_tenable_nessus_agent_detect_smb.sc" );
	script_mandatory_keys( "tenable/nessus_agent/detected" );
	script_tag( name: "summary", value: "Tenable Nessus Agent is prone to a local arbitrary code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability in Nessus Agent for Windows could allow an authenticated local
  attacker to execute arbitrary code by copying user-supplied files to a specially constructed path in a
  specifically named user directory." );
	script_tag( name: "impact", value: "A local authenticated attacker my execute arbitrary code. The attacker needs
  valid credentials on the Windows system to exploit this vulnerability." );
	script_tag( name: "affected", value: "Tenable Nessus Agent versions 8.0.0 - 8.1.0." );
	script_tag( name: "solution", value: "Update to version 8.1.1 or later." );
	script_xref( name: "URL", value: "https://www.tenable.com/security/tns-2020-07" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "8.0.0", test_version2: "8.1.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.1.1", install_path: location );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

