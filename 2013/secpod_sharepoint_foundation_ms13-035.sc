CPE = "cpe:/a:microsoft:sharepoint_foundation";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902963" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_bugtraq_id( 58883 );
	script_cve_id( "CVE-2013-1289" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-04-10 11:17:19 +0530 (Wed, 10 Apr 2013)" );
	script_name( "Microsoft SharePoint Foundation HTML Sanitisation Component XSS Vulnerability (2821818)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2810059" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-035" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_sharepoint_sever_n_foundation_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to bypass certain security
  restrictions and conduct cross-site scripting and spoofing attacks." );
	script_tag( name: "affected", value: "Microsoft SharePoint Foundation 2010 Service Pack 1." );
	script_tag( name: "insight", value: "Certain unspecified input is not properly sanitized within the HTML
  Sanitation component before being returned to the user. This can be
  exploited to execute arbitrary HTML and script code in a user's
  browser session in context of an affected site." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS13-035." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
version = get_app_version( cpe: CPE );
if(!version){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Shared Tools\\Web Server Extensions\\14.0";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
dllPath = registry_get_sz( key: key, item: "Location" );
if(dllPath){
	dllVer = fetch_file_version( sysPath: dllPath, file_name: "BIN\\Onetutil.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "14.0", test_version2: "14.0.6137.5001" )){
			report = report_fixed_ver( installed_version: dllVer, vulnerable_range: "14.0 - 14.0.6137.5001", install_path: dllPath );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}

