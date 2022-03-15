if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801654" );
	script_version( "$Revision: 12653 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "VMware 2 Web Server Directory Traversal Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15617/" );
	script_xref( name: "URL", value: "http://www.vul.kr/vmware-2-web-server-directory-traversal" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_vmware_prdts_detect_win.sc" );
	script_mandatory_keys( "VMware/Server/Win/Ver", "VMware/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to disclose sensitive
  information." );
	script_tag( name: "affected", value: "VMware Web Server Version 2.0.2" );
	script_tag( name: "insight", value: "The flaw is due to an error while handling certain requests, which
  can be exploited to download arbitrary files from the host system." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with VMware 2 Web Server and is prone to
  directory traversal vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!get_kb_item( "VMware/Win/Installed" )){
	exit( 0 );
}
vmserVer = get_kb_item( "VMware/Server/Win/Ver" );
if(vmserVer){
	if(version_is_equal( version: vmserVer, test_version: "2.0.2" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

