CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809468" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-7857", "CVE-2016-7858", "CVE-2016-7859", "CVE-2016-7860", "CVE-2016-7861", "CVE-2016-7862", "CVE-2016-7863", "CVE-2016-7864", "CVE-2016-7865" );
	script_bugtraq_id( 94153 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-11-09 11:24:45 +0530 (Wed, 09 Nov 2016)" );
	script_name( "Adobe Flash Player Security Updates(apsb16-37) - Windows" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A type confusion vulnerabilities.

  - An use-after-free vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to take control of the
  affected system, and lead to code execution." );
	script_tag( name: "affected", value: "Adobe Flash Player version 22.x
  before 23.0.0.207 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player
  23.0.0.207, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb16-37.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!playerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: playerVer, test_version: "22.0", test_version2: "23.0.0.206" )){
	report = report_fixed_ver( installed_version: playerVer, fixed_version: "23.0.0.207" );
	security_message( data: report );
	exit( 0 );
}

