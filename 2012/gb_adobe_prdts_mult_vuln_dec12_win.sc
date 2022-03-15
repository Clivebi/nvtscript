CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803074" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_cve_id( "CVE-2012-5676", "CVE-2012-5677", "CVE-2012-5678" );
	script_bugtraq_id( 56892, 56896, 56898 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-12-14 15:06:52 +0530 (Fri, 14 Dec 2012)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities - December12 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51560" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027854" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2016/2755801" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb12-27.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code or denial of service." );
	script_tag( name: "affected", value: "Adobe Flash Player version before 10.3.183.48, 11.x before 11.5.502.135 on Windows" );
	script_tag( name: "insight", value: "Multiple unspecified errors and integer overflow exists that could lead to
  code execution." );
	script_tag( name: "solution", value: "Update to Adobe Flash Player version 10.3.183.48 or 11.5.502.135 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities." );
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
if(version_is_less( version: vers, test_version: "10.3.183.48" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "11.5.502.134" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "10.3.183.48 or 11.5.502.135", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

