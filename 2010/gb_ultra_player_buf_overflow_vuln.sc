if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801207" );
	script_version( "$Revision: 12602 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)" );
	script_bugtraq_id( 35956 );
	script_cve_id( "CVE-2009-4863" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "UltraPlayer Media Player Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/52281" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2160" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9368" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute
arbitrary code within the context of the affected application." );
	script_tag( name: "affected", value: "UltraPlayer Media Player 2.112" );
	script_tag( name: "insight", value: "The flaw is caused by improper bounds checking when parsing
malicious '.usk' files. By tricking a victim to open a specially crafted
.usk file, an attacker could exploit this vulnerability." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with UltraPlayer Media Player and is
  prone to buffer overflow vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("version_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
upPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\App Paths\\UPlayer.exe", item: "Path" );
if(!upPath){
	exit( 0 );
}
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: upPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: upPath + "\\UPlayer.exe" );
upVer = GetVer( share: share, file: file );
if(upVer){
	if(version_is_equal( version: upVer, test_version: "2.1.1.2" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

