if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902423" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2012-0019", "CVE-2012-0020", "CVE-2012-0136", "CVE-2012-0137", "CVE-2012-0138" );
	script_bugtraq_id( 51903, 51904, 51906, 51907, 51908 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-02-15 09:34:05 +0530 (Wed, 15 Feb 2012)" );
	script_name( "Microsoft Office Visio Viewer Remote Code Execution Vulnerabilities (2663510)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/887012" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2597170" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-015" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/VisioViewer/Ver" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to gain same user rights as
  the logged on user and execute arbitrary code." );
	script_tag( name: "affected", value: "Microsoft Visio Viewer 2010 Service Pack 1 and prior." );
	script_tag( name: "insight", value: "The flaws are due to an unspecified error when validating certain
  data in specially crafted Visio files, this can be exploited to corrupt memory." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS12-015." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
vvVer = get_kb_item( "SMB/Office/VisioViewer/Ver" );
if(vvVer && IsMatchRegexp( vvVer, "^14\\..*" )){
	visioPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
	if(visioPath){
		dllPath = visioPath + "\\Microsoft Office\\Office14\\";
		if(dllPath){
			visiovVer = fetch_file_version( sysPath: dllPath, file_name: "VVIEWER.dll" );
			if(visiovVer){
				if(version_in_range( version: visiovVer, test_version: "14.0", test_version2: "14.0.6114.5000" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
			}
		}
	}
}

