if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803700" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-05-21 12:05:19 +0530 (Tue, 21 May 2013)" );
	script_name( "D-Link Dsl Router Multiple Authentication Bypass Vulnerabilities" );
	script_xref( name: "URL", value: "http://1337day.com/exploit/20789" );
	script_xref( name: "URL", value: "http://w00t.pro/2013/05/19/17033" );
	script_xref( name: "URL", value: "http://www.allinfosec.com/2013/05/19/web-applications-dsl-router-d-link-bz_1-06-multiple-vulnerabilities" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "DSL_Router/banner" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to retrieve the
  administrator password and then access the device with full privileges.
  This will allow an attacker to launch further attacks." );
	script_tag( name: "affected", value: "D-Link Dsl Router BZ_1.06" );
	script_tag( name: "insight", value: "The web interface of Dsl Router routers expose several pages
  accessible with no authentication. These pages can be abused to access
  sensitive information concerning the device configuration, including the
  clear-text password for the administrative user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running D-Link Dsl Router and is prone to multiple
  authentication bypass vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(banner && !ContainsString( banner, "WWW-Authenticate: Basic realm=\"DSL Router\"" )){
	exit( 0 );
}
if(http_vuln_check( port: port, url: "/password.cgi", pattern: "pwdAdmin = '.*", extra_check: make_list( "pwdUser = '",
	 ">Access Control -- Passwords<",
	 "Access to your DSL router" ) )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

