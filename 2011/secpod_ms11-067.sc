if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900299" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-11 06:41:03 +0200 (Thu, 11 Aug 2011)" );
	script_bugtraq_id( 49033 );
	script_cve_id( "CVE-2011-1976" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Microsoft Report Viewer Information Disclosure Vulnerability (2578230)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2548826" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2579115" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-067" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_ms_visual_prdts_detect.sc" );
	script_mandatory_keys( "Microsoft/VisualStudio/Ver" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary HTML and
  script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "- Microsoft Visual Studio 2005 Service Pack 1

  - Microsoft Report Viewer 2005 Service Pack 1 Re-distributable Package" );
	script_tag( name: "insight", value: "A flaw is due to an unspecified input passed to the Microsoft Report
  Viewer Control is not properly sanitised before being returned to the user." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS11-067." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
visStudVer = get_kb_item( "Microsoft/VisualStudio/Ver" );
if(visStudVer && IsMatchRegexp( visStudVer, "^8\\." )){
	if(( hotfix_missing( name: "2548826" ) == 1 )){
		studioPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\VisualStudio\\8.0", item: "InstallDir" );
		if(studioPath){
			reportViewPath = studioPath - "\\Common7\\IDE\\" + "\\ReportViewer";
			sysVer = fetch_file_version( sysPath: reportViewPath, file_name: "Microsoft.ReportViewer.WebForms.dll" );
			if(sysVer && IsMatchRegexp( sysVer, "^8\\." )){
				if(version_in_range( version: sysVer, test_version: "8.0", test_version2: "8.0.50727.5676" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
			}
		}
	}
}
key = "SOFTWARE\\Microsoft\\ReportViewer";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
if(( hotfix_missing( name: "2579115" ) == 0 )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	path = registry_get_sz( key: key + item, item: "Path" );
	if(ContainsString( path, "\\Microsoft.NET\\Framework" )){
		reportViewPath = path + "\\Microsoft Report Viewer Redistributable 2005";
		sysVer = fetch_file_version( sysPath: reportViewPath, file_name: "Install.res.1025.dll" );
		if(sysVer && IsMatchRegexp( sysVer, "^8\\." )){
			if(version_in_range( version: sysVer, test_version: "8.0.50727", test_version2: "8.0.50727.5676" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

