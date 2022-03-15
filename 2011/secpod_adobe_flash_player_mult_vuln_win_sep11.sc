CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902738" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)" );
	script_cve_id( "CVE-2011-2426", "CVE-2011-2427", "CVE-2011-2428", "CVE-2011-2429", "CVE-2011-2430", "CVE-2011-2444" );
	script_bugtraq_id( 49714, 49715, 49716, 49718, 49717, 49710 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities September-2011 (Windows)" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb11-26.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary code or cause
  a denial of service." );
	script_tag( name: "affected", value: "Adobe Flash Player versions prior to 10.3.183.10 on Windows." );
	script_tag( name: "insight", value: "The flaws are due to

  - Stack-based buffer overflow in the ActionScript Virtual Machine (AVM)
    component, allows remote attackers to execute arbitrary code via
    unspecified vectors.

  - logic error issue, allows attackers to execute arbitrary code or cause a
    denial of service (browser crash) via unspecified vectors.

  - security control bypass, allows attackers to bypass intended access
    restrictions and obtain sensitive information via unspecified vectors

  - logic error vulnerability, allows remote attackers to execute arbitrary
    code via crafted streaming media.

  - Cross-site scripting (XSS) vulnerability, allows remote attackers to
    inject arbitrary web script or HTML via a crafted URL." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version 10.3.183.10 or later." );
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
if(version_is_less( version: vers, test_version: "10.3.183.10" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "10.3.183.10", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

