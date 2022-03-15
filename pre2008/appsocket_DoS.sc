if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11090" );
	script_version( "2019-04-24T07:26:10+0000" );
	script_tag( name: "last_modification", value: "2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "AppSocket DoS" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "This script is Copyright (C) 2002 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 35, 2501, 9100 );
	script_tag( name: "solution", value: "Change your settings or firewall your printer." );
	script_tag( name: "summary", value: "It seems that it is possible to lock out your printer from the
  network by opening a few connections and keeping them open." );
	script_tag( name: "insight", value: "Note that the AppSocket protocol is so crude that the scanner
  cannot check if it is really running behind this port. This means a different service might be
  running behind this port and could have stopped responding as well." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
func test_app_socket( port ){
	if(!get_port_state( port )){
		return ( 0 );
	}
	soc = open_sock_tcp( port );
	if(!soc){
		return ( 0 );
	}
	s[0] = soc;
	for(i = 1;i < 16;i++){
		soc = open_sock_tcp( port );
		if(!soc){
			security_message( port: port );
			for(j = 0;j < i;j++){
				close( s[j] );
			}
			return ( 1 );
		}
		sleep( 1 );
		s[i] = soc;
	}
	for(j = 0;j < i;j++){
		close( s[j] );
	}
	return ( 0 );
}
test_app_socket( port: 35 );
test_app_socket( port: 2501 );
test_app_socket( port: 9100 );

