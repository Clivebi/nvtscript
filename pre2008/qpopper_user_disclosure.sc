if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12279" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 7110 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "QPopper Username Information Disclosure" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 Scott Shebby" );
	script_family( "General" );
	script_dependencies( "popserver_detect.sc" );
	script_require_ports( "Services/pop3", 110, 995 );
	script_mandatory_keys( "pop3/qpopper/detected" );
	script_tag( name: "summary", value: "The remote server appears to be running a version of QPopper
  that is older than 4.0.6." );
	script_tag( name: "impact", value: "Versions older than 4.0.6 are vulnerable to a bug where remote
  attackers can enumerate valid usernames based on server responses during the authentication process." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("pop3_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = pop3_get_port( default: 110 );
banner = pop3_get_banner( port: port );
if(!banner || !ContainsString( banner, "Qpopper" )){
	exit( 0 );
}
if(ereg( pattern: ".*Qpopper.*version ([0-3]\\.*|4\\.0\\.[0-5][^0-9]).*", string: banner, icase: TRUE )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

