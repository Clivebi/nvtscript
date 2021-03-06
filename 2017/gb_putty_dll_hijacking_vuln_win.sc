CPE = "cpe:/a:putty:putty";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810541" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-09 14:25:24 +0530 (Thu, 09 Feb 2017)" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-09 20:00:00 +0000 (Tue, 09 Oct 2018)" );
	script_cve_id( "CVE-2016-6167" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PuTTY DLL Hijacking Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_putty_portable_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "putty/detected" );
	script_tag( name: "summary", value: "PuTTY is prone to a dll hijacking vulnerability." );
	script_tag( name: "insight", value: "The flaw is due to multiple untrusted search
  path errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the affected application.
  Failed exploit attempts will result in a denial of service condition." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "PuTTY beta 0.67 (Windows installers
  created by Inno Setup for version 0.67) on Windows." );
	script_tag( name: "solution", value: "Upgrade to PuTTY version 0.67 or later
  (MSI format for PuTTY's Windows installer (generated by the WiX toolset))." );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/137742" );
	script_xref( name: "URL", value: "http://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html" );
	script_xref( name: "URL", value: "http://www.chiark.greenend.org.uk/~sgtatham/putty" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PuTTY_is1";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PuTTY_is1";
	}
}
if(version_is_equal( version: version, test_version: "0.67" )){
	inno_location = registry_get_sz( key: key, item: "Inno Setup: App Path" );
	if(!inno_location){
		exit( 0 );
	}
	report = report_fixed_ver( installed_version: version, fixed_version: "0.67 (MSI format for PuTTY's Windows installer)", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

