if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117401" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_cve_id( "CVE-2021-21551" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-05-07 12:27:53 +0000 (Fri, 07 May 2021)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-27 16:14:00 +0000 (Thu, 27 May 2021)" );
	script_name( "Dell Client Platform 'dbutil Driver' Insufficient Access Control Vulnerability (DSA-2021-088)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc", "gb_wmi_access.sc", "lsc_options.sc" );
	script_mandatory_keys( "WMI/access_successful", "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_exclude_keys( "win/lsc/disable_wmi_search", "win/lsc/disable_win_cmd_exec" );
	script_tag( name: "summary", value: "The Dell Client Platform 'dbutil Driver' is prone to an
  access control vulnerability." );
	script_tag( name: "vuldetect", value: "Checks via WMI if the vulnerable dbutil_2_3.sys file exists on
  the target system. If a file was found, checks via PowerShell, if the sha256 file hash is matching
  the hash of the known vulnerable driver." );
	script_tag( name: "insight", value: "Dell dbutil_2_3.sys driver contains an insufficient access
  control vulnerability which may lead to escalation of privileges, denial of service, or
  information disclosure. Local authenticated user access is required." );
	script_tag( name: "solution", value: "Remove the vulnerable dbutil_2_3.sys file from the target.
  Alternatively apply the updates provided by the vendor in the linked references. Please see
  the references for more details." );
	script_xref( name: "URL", value: "https://www.dell.com/support/kbdoc/en-us/000186019/dsa-2021-088-dell-client-platform-security-update-for-dell-driver-insufficient-access-control-vulnerability" );
	script_xref( name: "URL", value: "https://www.dell.com/support/kbdoc/en-us/000186020/additional-information-regarding-dsa-2021-088-dell-driver-insufficient-access-control-vulnerability" );
	script_xref( name: "URL", value: "https://labs.sentinelone.com/cve-2021-21551-hundreds-of-millions-of-dell-computers-at-risk-due-to-multiple-bios-driver-privilege-escalation-flaws/" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("wmi_file.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
if(get_kb_item( "win/lsc/disable_wmi_search" ) || get_kb_item( "win/lsc/disable_win_cmd_exec" ) || !defined_func( "win_cmd_exec" )){
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
file_list = wmi_file_file_search( handle: handle, fileName: "dbutil_2_3", fileExtn: "sys", includeHeader: FALSE );
wmi_close( wmi_handle: handle );
if(!file_list || !is_array( file_list )){
	exit( 0 );
}
affected_sha256sums_pattern = "(0296E2CE999E67C76352613A718E11516FE1B0EFC3FFDB8918FC999DD76A73A5|87E38E7AEAAAA96EFE1A74F59FCA8371DE93544B7AF22862EB0E574CEC49C7C3)";
report = "The vulnerable Dell driver was found based on the following information (Filename:sha256 file hash)\n";
for file in file_list {
	cmd = "powershell -Command \" & {Get-Filehash " + file + " -Algorithm SHA256}\"";
	result = win_cmd_exec( cmd: cmd, password: infos["password"], username: infos["username_wincmd"] );
	result = chomp( result );
	if(!result){
		return;
	}
	if(found = eregmatch( string: result, pattern: affected_sha256sums_pattern, icase: FALSE )){
		VULN = TRUE;
		report += "\n" + file + ":" + found[1];
	}
}
if(VULN){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

