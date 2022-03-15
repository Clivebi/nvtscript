if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812696" );
	script_version( "2021-06-30T11:00:43+0000" );
	script_cve_id( "CVE-2018-6654" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-30 11:00:43 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-02-08 14:22:37 +0530 (Thu, 08 Feb 2018)" );
	script_name( "Grammarly Extension For Google Chrome Information Disclosure Vulnerability - Windows" );
	script_tag( name: "summary", value: "The host is installed with Grammarly Spell
  Checker for Google Chrome and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as the extension exposes its
  auth tokens to all websites" );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  will allow any user to login 'grammarly.com' as victim and access all his documents,
  history, logs, and all other data." );
	script_tag( name: "affected", value: "Grammarly extension before 14.826.1446 for
  Chrome on Windows" );
	script_tag( name: "solution", value: "Upgrade to Grammarly extension 14.826.1446
  or later. Please see the references for more info." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod", value: "75" );
	script_xref( name: "URL", value: "https://bugs.chromium.org/p/project-zero/issues/detail?id=1527&desc=2" );
	script_xref( name: "URL", value: "https://thehackernews.com/2018/02/grammar-checking-software.html" );
	script_xref( name: "URL", value: "https://www.grammarly.com/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc", "smb_reg_service_pack.sc", "gb_wmi_access.sc", "lsc_options.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver", "WMI/access_successful", "SMB/WindowsVersion" );
	script_exclude_keys( "win/lsc/disable_wmi_search" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("misc_func.inc.sc");
require("wmi_file.inc.sc");
require("list_array_func.inc.sc");
if(get_kb_item( "win/lsc/disable_wmi_search" )){
	exit( 0 );
}
infos = kb_smb_wmi_connectinfo();
if(!infos){
	exit( 0 );
}
handle = wmi_connect( host: infos["host"], username: infos["username_wmi_smb"], password: infos["password"] );
if(!handle){
	exit( 0 );
}
fileList = wmi_file_file_search( handle: handle, dirPathLike: "%google%chrome%extensions%", fileName: "Grammarly", fileExtn: "html", includeHeader: FALSE );
wmi_close( wmi_handle: handle );
if(!fileList || !is_array( fileList )){
	exit( 0 );
}
report = "";
for filePath in fileList {
	info = eregmatch( pattern: "(.*(g|G)oogle.(c|C)hrome.*(e|E)xtensions.*[A-za-z]+\\\\([0-9.]+).*)(g|G)rammarly.html", string: filePath );
	if(!info[5]){
		continue;
	}
	version = info[5];
	path = info[1];
	if(version_is_less( version: version, test_version: "14.826.1446" )){
		VULN = TRUE;
		report += report_fixed_ver( installed_version: version, install_path: path, fixed_version: "14.826.1446" ) + "\n";
	}
}
if(VULN){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

