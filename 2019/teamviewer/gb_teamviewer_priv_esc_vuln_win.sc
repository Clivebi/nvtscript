CPE = "cpe:/a:teamviewer:teamviewer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142899" );
	script_version( "2021-09-08T10:01:41+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 10:01:41 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-09-17 07:18:26 +0000 (Tue, 17 Sep 2019)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-13 16:29:00 +0000 (Fri, 13 Sep 2019)" );
	script_cve_id( "CVE-2019-11769" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "TeamViewer < 14.4.2669 Insufficiently Protected Administrator Credentials Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_teamviewer_win_detect.sc" );
	script_mandatory_keys( "teamviewer/Ver" );
	script_tag( name: "summary", value: "TeamViewer is prone to a vulnerability where Windows Admin account credentials
  can be provided to update TeamViewer." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Teamviewer allows local attackers under the same user context as the running
  application to intercept user-provided administrative account credentials during its update process." );
	script_tag( name: "impact", value: "A local attacker might use this vulnerability to conduct a privilege
  escalation attack." );
	script_tag( name: "solution", value: "Update to version 14.4.2669 or later." );
	script_xref( name: "URL", value: "https://blog.to.com/advisory-teamviewer-cve-2019-11769-2/" );
	script_xref( name: "URL", value: "https://community.teamviewer.com/t5/Change-Logs/Windows-v14-4-2669-Full-Change-Log/m-p/66731" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "14.4.2669" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "14.4.2669", install_path: location );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

