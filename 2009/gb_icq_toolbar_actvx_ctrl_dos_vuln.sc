if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800694" );
	script_version( "$Revision: 12602 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-7135", "CVE-2008-7136" );
	script_bugtraq_id( 28086, 28118 );
	script_name( "ICQ Toolbar 'toolbaru.dll' ActiveX Control Remote DOS Vulnerability" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/5217" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/41014" );
	script_xref( name: "URL", value: "http://www.securiteam.com/exploits/5WP0115NPU.html" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_icq_toolbar_detect.sc" );
	script_mandatory_keys( "ICQ/Toolbar/Ver" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to crash the
toolbar." );
	script_tag( name: "affected", value: "ICQ Toolbar version 2.3 beta and prior." );
	script_tag( name: "insight", value: "This flaw is due to an error in 'toolbaru.dll' when processing
a long argument to the (1) RequestURL, (2) GetPropertyById, (3) SetPropertyById
or (4) IsChecked method." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host has ICQ Toolbar installed and is prone to Remote
Denial of Service Vulnerability" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_activex.inc.sc");
require("secpod_smb_func.inc.sc");
icqVer = get_kb_item( "ICQ/Toolbar/Ver" );
if(!icqVer){
	exit( 0 );
}
path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\", item: "ProgramFilesDir" );
path = path + "\\ICQToolbar\\toolbaru.dll";
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: path );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: path );
dllSize = get_file_size( share: share, file: file );
if(dllSize){
	if(version_is_less_equal( version: icqVer, test_version: "2.3.beta" )){
		if(is_killbit_set( clsid: "{855F3B16-6D32-4FE6-8A56-BBB695989046" ) == 0){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}

