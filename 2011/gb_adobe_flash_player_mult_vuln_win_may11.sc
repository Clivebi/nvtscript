CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801792" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)" );
	script_cve_id( "CVE-2011-0579", "CVE-2011-0618", "CVE-2011-0619", "CVE-2011-0620", "CVE-2011-0621", "CVE-2011-0622", "CVE-2011-0623", "CVE-2011-0624", "CVE-2011-0625", "CVE-2011-0626", "CVE-2011-0627" );
	script_bugtraq_id( 47847, 47815, 47806, 47807, 47808, 47809, 47811, 47812, 47813, 47814, 47810 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities May-2011 (Windows)" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb11-12.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary code or cause
  a denial of service condition." );
	script_tag( name: "affected", value: "Adobe Flash Player version 10.2.159.1 and prior on Windows" );
	script_tag( name: "insight", value: "The flaws are caused by memory corruptions, integer overflow errors and bounds
  checking errors when processing malformed Flash content, which could be
  exploited by attackers to execute arbitrary code by tricking a user into
  visiting a specially crafted web page." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version 10.3.181.14 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "10.2.159.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "10.3.181.14", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

