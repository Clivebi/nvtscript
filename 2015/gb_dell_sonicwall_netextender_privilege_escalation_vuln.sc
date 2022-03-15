CPE = "cpe:/a:sonicwall:netextender";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806043" );
	script_version( "2020-08-10T07:16:42+0000" );
	script_cve_id( "CVE-2015-4173" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-10 07:16:42 +0000 (Mon, 10 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-09-08 13:38:49 +0530 (Tue, 08 Sep 2015)" );
	script_name( "Dell SonicWall NetExtender Privilege Escalation Vulnerability (Windows)" );
	script_tag( name: "summary", value: "Dell SonicWall NetExtender is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to Unquoted Windows
  search path vulnerability in the autorun value upon installation of the product." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  privileged code execution upon administrative login." );
	script_tag( name: "affected", value: "Dell SonicWall NetExtender version before
  7.5.227 and before 8.0.238 on Windows." );
	script_tag( name: "solution", value: "Upgrade to firmware version 7.5.227 or 8.0.238 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/133302" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_dell_sonicwall_netextender_detect_win.sc" );
	script_mandatory_keys( "Dell/SonicWall/NetExtender/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "7.5.227" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.5.227", install_path: location );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0", test_version2: "8.0.237" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0.238", install_path: location );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

