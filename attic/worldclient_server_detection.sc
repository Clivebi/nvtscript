if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10745" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2000-0660" );
	script_bugtraq_id( 1462, 2478, 4687, 4689, 823 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "WorldClient for MDaemon Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Noam Rathaus <noamr@securiteam.com> & SecuriTeam" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "WDaemon/banner" );
	script_require_ports( "Services/www", 3000 );
	script_xref( name: "URL", value: "http://www.securiteam.com/cgi-bin/htsearch?config=htdigSecuriTeam&words=WorldClient" );
	script_tag( name: "solution", value: "Make sure all usernames and passwords are adequately long and
  that only authorized networks have access to this web server's port number
  (block the web server's port number on your firewall)." );
	script_tag( name: "summary", value: "We detected the remote web server is
  running WorldClient for MDaemon. This web server enables attackers
  with the proper username and password combination to access locally
  stored mailboxes.

  In addition, earlier versions of WorldClient suffer from buffer overflow
  vulnerabilities, and web traversal problems (if those are found the Risk
  factor is higher)." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 3000 );
banner = http_get_remote_headers( port: port );
if(banner && egrep( pattern: "^Server: WDaemon/", string: banner )){
	log_message( port: port );
	buf = strstr( banner, "WDaemon/" );
	buf = banner - "WDaemon/";
	subbuf = strstr( buf, NASLString( "\\r\\n" ) );
	buf = buf - subbuf;
	version = buf;
	buf = "Remote WorldClient server version is: ";
	buf = buf + version;
	if(version < "4"){
		report = NASLString( "This version of WorldClient contains serious security vulnerabilities.\\n", "It is advisable that you upgrade to the latest version." );
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 99 );

