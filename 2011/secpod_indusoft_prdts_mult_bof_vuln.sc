if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902376" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)" );
	script_cve_id( "CVE-2011-0340" );
	script_bugtraq_id( 47596 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "InduSoft Products Multiple Buffer overflow Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43116" );
	script_xref( name: "URL", value: "http://www.indusoft.com/hotfixes/hotfixes.php" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/1116" );
	script_tag( name: "insight", value: "The flaw exists due to a buffer overflow error in the ISSymbol ActiveX
  control (ISSymbol.ocx) when processing an overly long 'InternationalOrder',
  'InternationalSeparator', 'bstrFileName' or 'LogFileName' property, which
  could be exploited by attackers to execute arbitrary code by tricking a user
  into visiting a specially crafted web page." );
	script_tag( name: "solution", value: "Install the hotfix" );
	script_tag( name: "summary", value: "This host is installed with Indusoft products and is prone
  to buffer overflow vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "InduSoft Thin Client version 7.0
  InduSoft Web Studio version before 7.0 SP1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
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
	{
		indPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(indPath){
			ocxVer = fetch_file_version( sysPath: indPath, file_name: "ISSymbol.ocx" );
			if(ocxVer){
				if(version_is_equal( version: ocxVer, test_version: "301.1009.2904.0" ) || version_is_equal( version: ocxVer, test_version: "61.6.0.0" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
	indName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( indName, "InduSoft Web Studio" )){
		indPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(indPath){
			ocxVer = fetch_file_version( sysPath: indPath, file_name: "bin\\ISSymbol.ocx" );
			if(ocxVer){
				if(version_is_equal( version: ocxVer, test_version: "301.1009.2904.0" ) || version_is_equal( version: ocxVer, test_version: "61.6.0.0" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
			}
		}
	}
}

