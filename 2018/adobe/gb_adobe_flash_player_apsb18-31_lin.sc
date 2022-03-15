CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814004" );
	script_version( "2021-06-01T06:00:14+0200" );
	script_cve_id( "CVE-2018-15967" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-01 06:00:14 +0200 (Tue, 01 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-09-12 10:44:09 +0530 (Wed, 12 Sep 2018)" );
	script_name( "Adobe Flash Player Security Updates(apsb18-31)-Linux" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a privilege escalation
  issue." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to disclose sensitive information." );
	script_tag( name: "affected", value: "Adobe Flash Player version before 31.0.0.108 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version
  31.0.0.108, or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb18-31.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "31.0.0.108" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "31.0.0.108", install_path: path );
	security_message( data: report );
	exit( 0 );
}

