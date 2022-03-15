if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900450" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-12-26 14:23:17 +0100 (Fri, 26 Dec 2008)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:N/A:P" );
	script_bugtraq_id( 31686 );
	script_cve_id( "CVE-2008-5666" );
	script_name( "WinFTP Server PASV Command Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32209" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/6717" );
	script_tag( name: "impact", value: "Successful exploitation will let the user crash the application to cause
  denial of service." );
	script_tag( name: "affected", value: "Win FTP Server version 2.3.0 or prior." );
	script_tag( name: "insight", value: "The flaw is due to an error when handling the PASV and NLST commands. These can
  be exploited through sending multiple login request ending with PASV command." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running WinFTP Server and is prone to Denial of
  Service Vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\WinFtp Server_is1";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
regKey = registry_get_sz( key: key, item: "DisplayName" );
if(!ContainsString( regKey, "WinFtp Server" )){
	exit( 0 );
}
winftpVer = eregmatch( pattern: "WinFtp Server ([0-9.]+)", string: regKey );
if(version_is_less_equal( version: winftpVer[1], test_version: "2.3.0" )){
	report = report_fixed_ver( installed_version: winftpVer, fixed_version: "WillNotFix" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

