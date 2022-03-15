if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800503" );
	script_version( "$Revision: 12602 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2009-01-15 16:11:17 +0100 (Thu, 15 Jan 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-5884" );
	script_bugtraq_id( 31572 );
	script_name( "AyeView GIF Image Handling Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/497045/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful remote exploitation could result in Denial of Service." );
	script_tag( name: "affected", value: "AyeView version 2.20 and prior on Windows." );
	script_tag( name: "insight", value: "Flaw is due to an error generated while handling GIF file. These .gif files
  contain a malformed header." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host has AyeView Image Viewer installed and is prone to denial
  of service vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://www.ayeview.com/" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
verStr = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\Uninstall\\AyeView_is1", item: "DisplayName" );
if(!verStr){
	exit( 0 );
}
avVer = eregmatch( pattern: "AyeView version ([0-9.]+)", string: verStr );
if(!avVer[1] != NULL){
	exit( 0 );
}
if(version_is_less_equal( version: avVer[1], test_version: "2.20" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

