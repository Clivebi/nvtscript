CPE = "cpe:/a:bluestacks:bluestacks";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809786" );
	script_version( "2021-09-09T14:06:19+0000" );
	script_cve_id( "CVE-2016-4288" );
	script_bugtraq_id( 92426 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 14:06:19 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-01-10 16:21:00 +0000 (Tue, 10 Jan 2017)" );
	script_tag( name: "creation_date", value: "2017-01-24 15:57:11 +0530 (Tue, 24 Jan 2017)" );
	script_name( "BlueStacks App Player Privilege Escalation Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with BlueStacks App
  Player and is prone to privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as the installer creates a
  registry key with weak permissions." );
	script_tag( name: "impact", value: "Successful exploitation will allow users to
  execute arbitrary programs with SYSTEM privileges." );
	script_tag( name: "affected", value: "BlueStacks App Player version 2.1.3.5650" );
	script_tag( name: "solution", value: "Upgrade to BlueStacks App Player 2.4.43.6254
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.talosintelligence.com/reports/TALOS-2016-0124" );
	script_xref( name: "URL", value: "http://blog.talosintel.com/2016/08/bluestacks-app-player-vulnerability.html" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_bluestacks_app_player_detect_win.sc" );
	script_mandatory_keys( "Bluestacks/App/Player/Win/Ver" );
	script_xref( name: "URL", value: "http://www.bluestacks.com" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!blVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_equal( version: blVer, test_version: "2.1.3.5650" )){
	report = report_fixed_ver( installed_version: blVer, fixed_version: "2.4.43.6254 or later" );
	security_message( data: report );
	exit( 0 );
}

