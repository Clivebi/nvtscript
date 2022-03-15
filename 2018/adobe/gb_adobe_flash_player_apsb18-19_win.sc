CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813396" );
	script_version( "2021-05-31T06:00:15+0200" );
	script_cve_id( "CVE-2018-5002", "CVE-2018-4945", "CVE-2018-5000", "CVE-2018-5001" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-05-31 06:00:15 +0200 (Mon, 31 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-06-08 12:20:31 +0530 (Fri, 08 Jun 2018)" );
	script_name( "Adobe Flash Player Security Updates(apsb18-19)-Windows" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A type confusion error.

  - An integer overflow error.

  - An out-of-bounds read error.

  - A stack-based buffer overflow error." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct arbitrary code execution and disclosure of sensitive
  information." );
	script_tag( name: "affected", value: "Adobe Flash Player version before
  30.0.0.113 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version
  30.0.0.113, or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb18-19.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "30.0.0.113" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "30.0.0.113", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

