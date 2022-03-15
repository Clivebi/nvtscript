if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802601" );
	script_version( "$Revision: 11374 $" );
	script_bugtraq_id( 51666 );
	script_cve_id( "CVE-2012-0907" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-01 14:14:14 +0530 (Wed, 01 Feb 2012)" );
	script_name( "NeoAxis Web Player Zip File Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51666" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/72427" );
	script_xref( name: "URL", value: "http://aluigi.altervista.org/adv/neoaxis_1-adv.txt" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain sensitive
information that could aid in further attacks." );
	script_tag( name: "affected", value: "NeoAxis web player version 1.4 and prior" );
	script_tag( name: "insight", value: "The flaw is caused due by improper validation of the files
extracted from neoaxis_web_application_win32.zip file, which allows attackers
to write arbitrary files via directory traversal attacks." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with NeoAxis Web Player and is prone
to directory traversal vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\NeoAxis Web Player_is1";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
name = registry_get_sz( key: key, item: "DisplayName" );
if(ContainsString( name, "NeoAxis Web Player" )){
	version = registry_get_sz( key: key, item: "DisplayVersion" );
	if(version && version_is_less_equal( version: version, test_version: "1.4" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
exit( 99 );

