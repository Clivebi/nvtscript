CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811974" );
	script_version( "2021-09-10T09:01:40+0000" );
	script_cve_id( "CVE-2017-11292" );
	script_bugtraq_id( 101286 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-10 09:01:40 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-08 02:29:00 +0000 (Fri, 08 Dec 2017)" );
	script_tag( name: "creation_date", value: "2017-10-17 11:14:20 +0530 (Tue, 17 Oct 2017)" );
	script_name( "Adobe Flash Player Security Update (apsb17-32) - Linux" );
	script_tag( name: "summary", value: "Adobe Flash Player is prone to a remote code execution (RCE)
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a type confusion
  vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to conduct remote code execution." );
	script_tag( name: "affected", value: "Adobe Flash Player version before
  27.0.0.159." );
	script_tag( name: "solution", value: "Update to version 27.0.0.159 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb17-32.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_lin.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "27.0.0.159" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "27.0.0.159", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

