CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801629" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-11-12 15:34:28 +0100 (Fri, 12 Nov 2010)" );
	script_cve_id( "CVE-2010-3636", "CVE-2010-3637", "CVE-2010-3638", "CVE-2010-3639", "CVE-2010-3640", "CVE-2010-3641", "CVE-2010-3642", "CVE-2010-3643", "CVE-2010-3644", "CVE-2010-3645", "CVE-2010-3646", "CVE-2010-3647", "CVE-2010-3648", "CVE-2010-3649", "CVE-2010-3650", "CVE-2010-3652" );
	script_bugtraq_id( 44669 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41917" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb10-26.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary code or cause
  a denial of service via unknown vectors." );
	script_tag( name: "affected", value: "Adobe Flash Player version 10.1.85.3 and prior on Windows" );
	script_tag( name: "insight", value: "The flaws are caused by unspecified errors, that can be exploited to execute
  arbitrary code or cause a denial of service." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version 10.1.102.64 or later" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to
  multiple unspecified vulnerabilities." );
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
if(version_in_range( version: vers, test_version: "10", test_version2: "10.1.85.3" ) || version_is_less( version: vers, test_version: "9.0.289.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "10.1.102.64", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

