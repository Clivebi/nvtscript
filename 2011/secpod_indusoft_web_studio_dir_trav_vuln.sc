if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902371" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2011-1900" );
	script_bugtraq_id( 47842 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)" );
	script_name( "InduSoft Web Studio Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42883" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/67419" );
	script_xref( name: "URL", value: "http://www.indusoft.com/hotfixes/hotfixes.php" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "insight", value: "The flaw is due to an error in 'NTWebServer', which allows remote
  attackers to execute arbitrary code via an invalid request." );
	script_tag( name: "solution", value: "Install the hotfix from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with Indusoft Web Studio and is prone to
  directory traversal vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary code
  via an invalid request." );
	script_tag( name: "affected", value: "InduSoft Web Studio version 6.1 and 7.x before 7.0+Patch 1" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	indName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( indName, "InduSoft Web Studio" )){
		indVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(!indVer){
			exit( 0 );
		}
		indVer = eregmatch( string: indVer, pattern: "([0-9.]+)" );
		if(indVer[1]){
			if(version_is_equal( version: indVer[1], test_version: "6.1" ) || version_is_equal( version: indVer[1], test_version: "7.0" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

