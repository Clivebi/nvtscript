if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100075" );
	script_version( "$Revision: 12037 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-23 14:45:32 +0200 (Tue, 23 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2018-10-23 14:01:33 +0200 (Tue, 23 Oct 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "echo Service Reporting (TCP + UDP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Useless services" );
	script_dependencies( "echo.sc", "echo_udp.sc" );
	script_mandatory_keys( "echo_tcp_udp/detected" );
	script_xref( name: "URL", value: "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0635" );
	script_tag( name: "solution", value: "Disable the echo Service." );
	script_tag( name: "summary", value: "An echo Service is running at this Host via TCP and/or UDP.

  The echo service is an Internet protocol defined in RFC 862. It was
  originally proposed for testing and measurement of round-trip times in IP
  networks. While still available on most UNIX-like operating systems, testing
  and measurement is now performed with the Internet Control Message Protocol
  (ICMP), using the applications ping and traceroute." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
default_ports = make_list( 7 );
tcp_ports = get_kb_list( "Services/echo" );
if(!tcp_ports){
	tcp_ports = default_ports;
}
for tcp_port in tcp_ports {
	if(!get_kb_item( "echo_tcp/" + tcp_port + "/detected" )){
		continue;
	}
	security_message( port: tcp_port );
}
udp_ports = get_kb_list( "Services/udp/echo" );
if(!udp_ports){
	udp_ports = default_ports;
}
for udp_port in udp_ports {
	if(!get_kb_item( "echo_udp/" + tcp_port + "/detected" )){
		continue;
	}
	security_message( port: udp_port, protocol: "udp" );
}
exit( 0 );

