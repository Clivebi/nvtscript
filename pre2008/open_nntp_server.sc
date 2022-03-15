if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.17204" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_name( "Open News server" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "General" );
	script_dependencies( "nntp_info.sc" );
	script_require_ports( "Services/nntp", 119 );
	script_mandatory_keys( "nntp/detected" );
	script_tag( name: "summary", value: "The remote News server seems open to outsiders." );
	script_tag( name: "insight", value: "Some people love open public NNTP servers to be able to read and/or
  post articles anonymously.

  Keep in mind that robots are harvesting such open servers on Internet, so you cannot hope that
  you will stay hidden for long.

  Unwanted connections could waste your bandwidth or put you into legal trouble if outsiders use your server
  to read and/or post 'politically incorrects' articles.

  As it is very common to have IP based authentication, this might be a false positive if the scanner is
  among the allowed source addresses." );
	script_tag( name: "solution", value: "Enforce authentication or filter connections from outside" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("nntp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = nntp_get_port( default: 119 );
if(!get_kb_item( "nntp/" + port + "/ready" ) || !get_kb_item( "nntp/" + port + "/noauth" )){
	exit( 0 );
}
post = get_kb_item( "nntp/" + port + "/posting" );
if(post && get_kb_item( "nntp/" + port + "/posted" ) <= 0){
	post = 0;
}
if( !post ) {
	security_message( port: port, data: "Post is not affected" );
}
else {
	security_message( port: port, data: "Post is affected" );
}
exit( 0 );

