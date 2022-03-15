if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900042" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-09-02 07:39:00 +0200 (Tue, 02 Sep 2008)" );
	script_bugtraq_id( 30866 );
	script_cve_id( "CVE-2008-3282" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_name( "OpenOffice rtl_allocateMemory() Remote Code Execution Vulnerability (Windows)" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_xref( name: "URL", value: "http://secunia.com/advisories/31640/" );
	script_xref( name: "URL", value: "http://www.frsirt.com/english/advisories/2008/2449" );
	script_tag( name: "summary", value: "This host has OpenOffice.Org installed, which is prone to remote
  code execution vulnerability." );
	script_tag( name: "insight", value: "The issue is due to a numeric truncation error within the rtl_allocateMemory()
  method in alloc_global.c file." );
	script_tag( name: "affected", value: "OpenOffice.org 2.4.1 and prior on Windows." );
	script_tag( name: "solution", value: "Upgrade to OpenOffice.org Version 3.2.0 or later." );
	script_tag( name: "impact", value: "Attackers can cause an out of bounds array access by tricking a
  user into opening a malicious document, also allow execution of arbitrary code." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://download.openoffice.org/index.html" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
for item in registry_enum_keys( key: key ) {
	orgName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(orgName && ContainsString( orgName, "OpenOffice.org" )){
		orgVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(orgVer && egrep( pattern: "^([01]\\..*|2\\.([0-3](\\..*)?|4(\\.([0-8]?[0-9]?[0-9]?[0-9]|9[0-2][0-9][0-9]|930[0-9]|9310))?))$", string: orgVer )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
		exit( 99 );
	}
}
exit( 0 );

