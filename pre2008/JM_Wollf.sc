if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11881" );
	script_version( "2019-04-24T07:26:10+0000" );
	script_tag( name: "last_modification", value: "2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Wollf backdoor detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2003 J.Mlødzianøwski" );
	script_family( "Malware" );
	script_dependencies( "find_service2.sc" );
	script_require_ports( "Services/wollf" );
	script_xref( name: "URL", value: "http://www.rapter.net/jm4.htm" );
	script_tag( name: "solution", value: "See the references for details on the removal." );
	script_tag( name: "summary", value: "This host appears to be running Wollf on this port. Wollf Can be used as a
  Backdoor which allows an intruder gain remote access to files on your computer.

  If you did not install this program for remote management then this host may be compromised." );
	script_tag( name: "impact", value: "An attacker may use it to steal your passwords, or redirect
  ports on your system to launch other attacks" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
port = get_kb_item( "Services/wollf" );
if(port){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

