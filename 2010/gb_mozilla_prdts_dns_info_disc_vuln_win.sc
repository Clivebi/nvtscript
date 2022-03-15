if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800454" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-02-04 12:53:38 +0100 (Thu, 04 Feb 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-4630" );
	script_name( "Mozilla Products Information Disclosure Vulnerability (Windows)" );
	script_xref( name: "URL", value: "https://bugzilla.mozilla.org/show_bug.cgi?id=453403" );
	script_xref( name: "URL", value: "https://bugzilla.mozilla.org/show_bug.cgi?id=492196" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_seamonkey_detect_win.sc", "gb_firefox_detect_portable_win.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let the attackers obtain the network location of
  the applications user by logging DNS requests." );
	script_tag( name: "affected", value: "Mozilla Firefox and Seamonkey with Mozilla Necko version 1.9.0 and prior
  on Windows." );
	script_tag( name: "insight", value: "The flaw exists when DNS prefetching of domain names contained in links within
  local HTML documents." );
	script_tag( name: "summary", value: "The host is installed with Firefox/Seamonkey and is prone to
  Information Disclosure vulnerability." );
	script_tag( name: "solution", value: "Apply the patch or Upgrade to Mozilla Necko version 1.9.1." );
	script_xref( name: "URL", value: "https://bug453403.bugzilla.mozilla.org/attachment.cgi?id=346274" );
	script_xref( name: "URL", value: "http://www.mozilla.com/en-US/products/" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
smVer = get_kb_item( "Seamonkey/Win/Ver" );
if(!isnull( smVer )){
	path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\App Paths\\seamonkey.exe", item: "path" );
	if(!isnull( path )){
		path = path + "\\seamonkey.exe";
		share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: path );
		file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: path );
		seaVer = GetVer( file: file, share: share );
		if(!isnull( seaVer )){
			if(version_is_less( version: seaVer, test_version: "1.9.1" )){
				report = report_fixed_ver( installed_version: seaVer, fixed_version: "1.9.1", install_path: path );
				security_message( port: 0, data: report );
				exit( 0 );
			}
		}
	}
}
fpVer = get_kb_item( "Firefox/Win/Ver" );
if(!isnull( fpVer )){
	path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\App Paths\\firefox.exe", item: "path" );
	if(!isnull( path )){
		path = path + "\\firefox.exe";
		share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: path );
		file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: path );
		seaVer = GetVer( file: file, share: share );
		if(!isnull( seaVer )){
			if(version_is_less( version: seaVer, test_version: "1.9.1" )){
				report = report_fixed_ver( installed_version: seaVer, fixed_version: "1.9.1", install_path: path );
				security_message( port: 0, data: report );
				exit( 0 );
			}
		}
	}
}

