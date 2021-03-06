if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902346" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)" );
	script_cve_id( "CVE-2011-1065" );
	script_bugtraq_id( 46468 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "PIPI Player PIPIWebPlayer ActiveX Control Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43394" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/65537" );
	script_xref( name: "URL", value: "http://www.wooyun.org/bugs/wooyun-2010-01383" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "insight", value: "The flaw is due to an error when processing the 'PlayURL()' and
'PlayURLWithLocalPlayer()' methods. This can be exploited to cause a
stack-based buffer overflow via an overly long string passed to the methods." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with PIPI Player and is prone to buffer
overflow vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
arbitrary code in the context of the application." );
	script_tag( name: "affected", value: "PIPI Player version 2.8.0.0" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
	name = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( name, "PIPI" )){
		ver = eregmatch( pattern: "PIPI ([0-9.]+)", string: name );
		if(ver[1] != NULL){
			if(version_is_equal( version: ver[1], test_version: "2.8.0.0" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
	}
}

