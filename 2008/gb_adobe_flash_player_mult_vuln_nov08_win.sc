CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800054" );
	script_version( "2020-06-09T14:44:58+0000" );
	script_tag( name: "last_modification", value: "2020-06-09 14:44:58 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2008-11-12 16:32:06 +0100 (Wed, 12 Nov 2008)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-4818", "CVE-2008-4819", "CVE-2008-4820", "CVE-2008-4821", "CVE-2008-4822", "CVE-2008-4823", "CVE-2008-4824", "CVE-2008-5361", "CVE-2008-5362", "CVE-2008-5363" );
	script_bugtraq_id( 32129 );
	script_name( "Adobe Flash Player Multiple Vulnerabilities - Nov08 (Windows)" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb08-20.html" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb08-22.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Win/Installed" );
	script_tag( name: "impact", value: "Successful attack could allow malicious people to bypass certain
  security restrictions or manipulate certain data." );
	script_tag( name: "affected", value: "Adobe Flash Player 9.0.124.0 and earlier on Windows." );
	script_tag( name: "insight", value: "Multiple flaws are reported in Adobe Flash Player, please see the
  references for more information." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player 9.0.151.0 or 10.0.12.36." );
	script_tag( name: "summary", value: "This host has Adobe Flash Player installed and is prone to
  multiple security bypass vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "9.0.124.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "9.0.124.0", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

