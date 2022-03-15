if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900411" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)" );
	script_bugtraq_id( 32462 );
	script_cve_id( "CVE-2008-2712", "CVE-2008-3074", "CVE-2008-3075", "CVE-2008-3076" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_family( "General" );
	script_name( "Vim Shell Command Injection Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/30731/" );
	script_xref( name: "URL", value: "http://www.rdancer.org/vulnerablevim-shellescape.html" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary shell commands
  to compromise the system." );
	script_tag( name: "affected", value: "Vim version prior to 7.2 on Windows." );
	script_tag( name: "insight", value: "This error is due to the 'filetype.vim', 'tar.vim', 'zip.vim', 'xpm.vim',
  'xpm2.vim', 'gzip.vim', and 'netrw.vim' scripts which are insufficiently filtering escape characters." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to version 7.2." );
	script_tag( name: "summary", value: "This host is installed with Vim and is prone to Command Injection
  Vulnerability." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
entries = registry_enum_keys( key: key );
if(entries == NULL){
	exit( 0 );
}
for item in entries {
	ver = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( ver, "Vim" )){
		if(egrep( pattern: "Vim ([0-6](\\..*)?|7\\.[01](\\..*)?)", string: ver )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}

