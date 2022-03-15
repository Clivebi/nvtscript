CPE = "cpe:/a:adobe:adobe_air";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803813" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-2034", "CVE-2012-2035", "CVE-2012-2036", "CVE-2012-2037", "CVE-2012-2039", "CVE-2012-2038", "CVE-2012-2040" );
	script_bugtraq_id( 53887 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-07-11 15:04:41 +0530 (Thu, 11 Jul 2013)" );
	script_name( "Adobe Air Multiple Vulnerabilities June-2012 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49388" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027139" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb12-14.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "Adobe/Air/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or cause
  a denial of service (memory corruption) via unspecified vectors." );
	script_tag( name: "affected", value: "Adobe AIR version 3.2.0.2070 and prior on Windows" );
	script_tag( name: "insight", value: "Multiple errors are caused,

  - When parsing ActionScript.

  - Within NPSWF32.dll when parsing certain tags.

  - In the 'SoundMixer.computeSpectrum()' method, which can be exploited to
    bypass the same-origin policy.

  - In the installer allows planting a binary file." );
	script_tag( name: "solution", value: "Update to Adobe Air version 3.3.0.3610 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Air and is prone to multiple
  vulnerabilities." );
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
if(version_is_less_equal( version: vers, test_version: "3.2.0.2070" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.3.0.3610", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

