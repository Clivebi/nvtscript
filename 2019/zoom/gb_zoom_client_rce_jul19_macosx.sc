CPE = "cpe:/a:zoom:zoom";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815259" );
	script_version( "2021-09-30T13:55:33+0000" );
	script_cve_id( "CVE-2019-13567" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-30 13:55:33 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-07-19 16:27:34 +0530 (Fri, 19 Jul 2019)" );
	script_name( "Zoom Client RCE Vulnerability (ZSB-19003) - Mac OS X" );
	script_tag( name: "summary", value: "Zoom Client is prone to a remote code execution (RCE)
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a local web server which is running even
  after the application has been uninstalled and insecurely receives commands without validation and
  lets any website to interact with it." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  code with a maliciously crafted launch URL." );
	script_tag( name: "affected", value: "Zoom Client before version 4.4.53932.0709 on Mac OS X." );
	script_tag( name: "solution", value: "Update to version 4.4.53932.0709 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.zoom.us/hc/en-us/articles/201361963-New-Updates-for-Mac-OS" );
	script_xref( name: "URL", value: "https://blog.rapid7.com/2019/07/10/zoom-video-snooping-what-you-need-to-know/" );
	script_xref( name: "URL", value: "https://explore.zoom.us/en/trust/security/security-bulletin/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_zoom_client_detect_macosx.sc" );
	script_mandatory_keys( "zoom/client/mac/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "4.4.53932.0709" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.4.53932.0709", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

