CPE = "cpe:/a:tenable:nessus_agent";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.118114" );
	script_version( "2021-08-20T06:00:57+0000" );
	script_cve_id( "CVE-2021-20099", "CVE-2021-20100" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 06:00:57 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-01 19:18:00 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-06-16 16:11:43 +0200 (Wed, 16 Jun 2021)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Tenable Nessus Agent < 8.2.5 Multiple Vulnerabilities (TNS-2021-12)" );
	script_tag( name: "summary", value: "Tenable Nessus Agent is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "These vulnerabilities exist:

  - CVE-2021-20099, CVE-2021-20100: Multiple local privilege escalation vulnerabilities. A local
  attacker can exploit these to gain administrator privileges to the system." );
	script_tag( name: "affected", value: "Tenable Nessus Agent prior to version 8.2.5." );
	script_tag( name: "solution", value: "Update to version 8.2.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.tenable.com/security/tns-2021-12" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_tenable_nessus_agent_detect_smb.sc" );
	script_mandatory_keys( "tenable/nessus_agent/detected" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "8.2.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.2.5", install_path: path );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

