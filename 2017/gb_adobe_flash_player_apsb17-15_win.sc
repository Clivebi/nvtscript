CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811101" );
	script_version( "2021-09-14T09:01:51+0000" );
	script_cve_id( "CVE-2017-3068", "CVE-2017-3069", "CVE-2017-3070", "CVE-2017-3071", "CVE-2017-3072", "CVE-2017-3073", "CVE-2017-3074" );
	script_bugtraq_id( 98349, 98347 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 09:01:51 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "creation_date", value: "2017-05-10 07:59:40 +0530 (Wed, 10 May 2017)" );
	script_name( "Adobe Flash Player Security Update (apsb17-15) - Windows" );
	script_tag( name: "summary", value: "Adobe Flash Player is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A use-after-free vulnerability and

  - The memory corruption vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute the code." );
	script_tag( name: "affected", value: "Adobe Flash Player version before
  25.0.0.171." );
	script_tag( name: "solution", value: "Update to version 25.0.0.171 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb17-15.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "25.0.0.171" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "25.0.0.171", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

