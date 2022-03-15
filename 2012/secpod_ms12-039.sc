if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902842" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_bugtraq_id( 50462, 53335, 53831, 53833 );
	script_cve_id( "CVE-2011-3402", "CVE-2012-0159", "CVE-2012-1849", "CVE-2012-1858" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-06-13 11:11:11 +0530 (Wed, 13 Jun 2012)" );
	script_name( "Microsoft Lync Remote Code Execution Vulnerabilities (2707956)" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1027150" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-039" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_ms_lync_detect_win.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Lync/Installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to execute arbitrary code
  with kernel-level privileges. Failed exploit attempts may result in a
  denial of service condition." );
	script_tag( name: "affected", value: "- Microsoft Lync 2010

  - Microsoft Lync 2010 Attendee

  - Microsoft Lync 2010 Attendant

  - Microsoft Communicator 2007 R2" );
	script_tag( name: "insight", value: "- An error within the Win32k kernel-mode driver (win32k.sys) when parsing
    TrueType fonts.

  - An error in the t2embed.dll module when parsing TrueType fonts.

  - The client loads libraries in an insecure manner, which can be exploited
    to load arbitrary libraries by tricking a user into opening a '.ocsmeet'
    file located on a remote WebDAV or SMB share.

  - An unspecified error in the 'SafeHTML' API when sanitising HTML code can
    be exploited to execute arbitrary HTML and script code in the user's chat
    session." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS12-039." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(get_kb_item( "MS/Lync/Ver" )){
	path = get_kb_item( "MS/Lync/path" );
	if(path){
		commVer = fetch_file_version( sysPath: path, file_name: "communicator.exe" );
		if(commVer){
			if(version_in_range( version: commVer, test_version: "3.5", test_version2: "3.5.6907.252" ) || version_in_range( version: commVer, test_version: "4.0", test_version2: "4.0.7577.4097" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
if(get_kb_item( "MS/Lync/Attendee/Ver" )){
	path = get_kb_item( "MS/Lync/Attendee/path" );
	if(path){
		oglVer = fetch_file_version( sysPath: path, file_name: "Ogl.dll" );
		if(oglVer){
			if(version_in_range( version: oglVer, test_version: "4.0", test_version2: "4.0.7577.4097" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
if(get_kb_item( "MS/Lync/Attendant/Ver" )){
	path = get_kb_item( "MS/Lync/Attendant/path" );
	if(path){
		attVer = fetch_file_version( sysPath: path, file_name: "AttendantConsole.exe" );
		if(attVer){
			if(version_in_range( version: attVer, test_version: "4.0", test_version2: "4.0.7577.4097" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

