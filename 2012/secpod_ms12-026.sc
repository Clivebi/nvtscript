if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903018" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2012-0146", "CVE-2012-0147" );
	script_bugtraq_id( 52909, 52903 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-04-12 16:00:48 +0530 (Thu, 12 Apr 2012)" );
	script_name( "MS Forefront Unified Access Gateway Information Disclosure Vulnerability (2663860)" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/74367" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/74368" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/74369" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1026909" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-026" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_forefront_unified_access_gateway_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Forefront/UAG/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to obtain potentially sensitive
  information." );
	script_tag( name: "affected", value: "- Microsoft Forefront Unified Access Gateway 2010 Service Pack 1

  - Microsoft Forefront Unified Access Gateway 2010 Service Pack 1 Update 1" );
	script_tag( name: "insight", value: "The flaws are due to an error,

  - In UAG allows redirecting users to an untrusted site.

  - Within the default website configuration allows access to certain content
    from the external network." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS12-026." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
uagVer = get_kb_item( "MS/Forefront/UAG/Ver" );
if(!uagVer){
	exit( 0 );
}
path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
if(!path){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: path, file_name: "Microsoft Forefront Unified Access Gateway\\von\\bin\\Whlfilter.dll" );
if(!dllVer){
	exit( 0 );
}
if(version_in_range( version: dllVer, test_version: "4.0.1752.10000", test_version2: "4.0.1753.10075" ) || version_in_range( version: dllVer, test_version: "4.0.1773.10100", test_version2: "4.0.1773.10189" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

