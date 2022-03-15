if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.20161" );
	script_version( "2019-04-10T13:42:28+0000" );
	script_tag( name: "last_modification", value: "2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Cheops NG without password" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2005 Michel Arboi" );
	script_family( "General" );
	script_dependencies( "cheopsNG_detect.sc" );
	script_mandatory_keys( "cheopsNG/unprotected" );
	script_tag( name: "solution", value: "Restrict access to this port or enable authentication by starting the
  agent using the '-p' option." );
	script_tag( name: "summary", value: "The remote service does not require a password for access." );
	script_tag( name: "insight", value: "The Cheops NG agent on the remote host is running without
  authentication. Anyone can connect to this service and use it to map
  the network, port scan machines and identify running services." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
port = get_kb_item( "cheopsNG/unprotected" );
if(port){
	security_message( port: port );
}

