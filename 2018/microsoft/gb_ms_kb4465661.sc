if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814272" );
	script_version( "2021-06-24T02:00:31+0000" );
	script_cve_id( "CVE-2018-8566" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-24 02:00:31 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-11-14 09:55:34 +0530 (Wed, 14 Nov 2018)" );
	script_name( "MS Windows Security Bypass and Latest Servicing Stack Updates- Defense in Depth (KB4465661)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4465661." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "A security feature bypass flaw exists when
  Windows improperly suspends BitLocker Device Encryption. Also Microsoft has
  released latest servicing stack updates that provides enhanced security as a
  defense in depth measure." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to bypass a security control." );
	script_tag( name: "affected", value: "Microsoft Windows 10 version 1709 for 32-bit/x64." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4465661" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8566" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV990001" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc", "gb_wmi_access.sc", "lsc_options.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "WMI/access_successful" );
	script_exclude_keys( "win/lsc/disable_wmi_search" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("misc_func.inc.sc");
require("wmi_file.inc.sc");
require("list_array_func.inc.sc");
if(hotfix_check_sp( win10: 1, win10x64: 1 ) <= 0){
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
fileList = wmi_file_fileversion( handle: handle, fileName: "smiengine", fileExtn: "dll", includeHeader: FALSE );
wmi_close( wmi_handle: handle );
if(!fileList || !is_array( fileList )){
	exit( 0 );
}
max_version = "";
for filePath in keys( fileList ) {
	vers = fileList[filePath];
	if(IsMatchRegexp( vers, "^10\\.0" ) && version = eregmatch( string: vers, pattern: "^([0-9.]+)" )){
		if( max_version && version_is_less_equal( version: version[1], test_version: max_version ) ){
			continue;
		}
		else {
			max_version = version[1];
			path = filePath;
		}
	}
}
if(max_version && version_in_range( version: max_version, test_version: "10.0.16299.0", test_version2: "10.0.16299.781" )){
	report = report_fixed_ver( file_checked: path, file_version: max_version, vulnerable_range: "10.0.16299.0 - 10.0.16299.781" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

