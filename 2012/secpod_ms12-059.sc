if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902921" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2012-1888" );
	script_bugtraq_id( 54934 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-08-15 09:48:21 +0530 (Wed, 15 Aug 2012)" );
	script_name( "Microsoft Office Visio/Viewer Remote Code Execution Vulnerability (2733918)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2597171" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2598287" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-059" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to gain same user rights as
  the logged on user and execute arbitrary code." );
	script_tag( name: "affected", value: "- Microsoft Visio 2010 Service Pack 1 and prior

  - Microsoft Visio Viewer 2010 Service Pack 1 and prior" );
	script_tag( name: "insight", value: "Error in the way that Microsoft Office Visio/Viewer validates data when
  parsing specially crafted Visio files and can be exploited to corrupt memory
  via a specially crafted Visio file." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS12-059." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-059" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
sysPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\App Paths\\visio.exe", item: "Path" );
if(sysPath){
	exeVer = fetch_file_version( sysPath: sysPath, file_name: "visio.exe" );
	if(exeVer){
		if(version_in_range( version: exeVer, test_version: "14.0", test_version2: "14.0.6122.4999" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
vvVer = get_kb_item( "SMB/Office/VisioViewer/Ver" );
if(vvVer && IsMatchRegexp( vvVer, "^14\\..*" )){
	if(version_in_range( version: vvVer, test_version: "14.0", test_version2: "14.0.6116.4999" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

