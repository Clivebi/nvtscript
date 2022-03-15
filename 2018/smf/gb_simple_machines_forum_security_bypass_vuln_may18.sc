CPE = "cpe:/a:simplemachines:smf";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812886" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_cve_id( "CVE-2018-10305" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-05-14 16:42:36 +0530 (Mon, 14 May 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Simple Machines Forum Security Bypass Vulnerability May18" );
	script_tag( name: "summary", value: "This host is running Simple Machines Forum and is
  prone to security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as the 'MessageSearch2' function
  in PersonalMessage.php script in Simple Machines Forum (SMF) does not properly use
  the 'possible_users' variable in a query." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to bypass intended access restrictions." );
	script_tag( name: "affected", value: "Simple Machines Forum versions before 2.0.15" );
	script_tag( name: "solution", value: "Upgrade to Simple Machines Forum version
  2.0.15 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.simplemachines.org/community/index.php?topic=557176.0" );
	script_xref( name: "URL", value: "https://download.simplemachines.org/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_simple_machines_forum_detect.sc" );
	script_mandatory_keys( "SMF/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!sport = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: sport, exit_no_version: TRUE )){
	exit( 0 );
}
sver = infos["version"];
spath = infos["location"];
if(version_is_less( version: sver, test_version: "2.0.15" )){
	report = report_fixed_ver( installed_version: sver, fixed_version: "2.0.15", install_path: spath );
	security_message( port: sport, data: report );
	exit( 0 );
}
exit( 0 );

