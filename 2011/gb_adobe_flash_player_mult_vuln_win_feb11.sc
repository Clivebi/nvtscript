CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801847" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-02-15 08:14:35 +0100 (Tue, 15 Feb 2011)" );
	script_cve_id( "CVE-2011-0558", "CVE-2011-0559", "CVE-2011-0560", "CVE-2011-0561", "CVE-2011-0571", "CVE-2011-0572", "CVE-2011-0573", "CVE-2011-0574", "CVE-2011-0575", "CVE-2011-0577", "CVE-2011-0578", "CVE-2011-0607", "CVE-2011-0608" );
	script_bugtraq_id( 46186, 46188, 46189, 46190, 46191, 46192, 46193, 46194, 46195, 46196, 46197, 46282, 46283 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities February-2011 (Windows)" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0336" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb11-02.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary code or cause
  a denial of service." );
	script_tag( name: "affected", value: "Adobe Flash Player versions prior to 10.2.152.26 on Windows" );
	script_tag( name: "insight", value: "The flaws are caused by input validation errors, memory corruptions, and
  integer overflow errors when processing malformed Flash content, which could
  be exploited by attackers to execute arbitrary code by tricking a user into
  visiting a specially crafted web page." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version 10.2.152.26 or later." );
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
if(version_is_less( version: vers, test_version: "10.2.152.26" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "10.2.152.26", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

