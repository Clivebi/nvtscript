if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802370" );
	script_version( "$Revision: 11374 $" );
	script_cve_id( "CVE-2011-5043" );
	script_bugtraq_id( 51123 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2012-01-05 12:20:03 +0530 (Thu, 05 Jan 2012)" );
	script_name( "TomatoSoft Free Mp3 Player '.mp3' File Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/71870" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18254/" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause the
application to crash." );
	script_tag( name: "affected", value: "TomatoSoft Free Mp3 Player 1.0" );
	script_tag( name: "insight", value: "The flaw is due to an error when parsing a crafted '.mp3' file
containing an overly long argument." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with TomatoSoft Free Mp3 Player and is
prone to denial of service vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Mp3Player";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
playerName = registry_get_sz( key: key, item: "Publisher" );
if(ContainsString( playerName, "Tomatosoft" )){
	playerVer = registry_get_sz( key: key, item: "DisplayName" );
	playerVer = eregmatch( pattern: "Mp3 Player ([0-9.]+)", string: playerVer );
	if(playerVer != NULL){
		if(version_is_less_equal( version: playerVer[1], test_version: "1.0" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}

