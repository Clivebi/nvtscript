if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12222" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-1978" );
	script_bugtraq_id( 10251 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Moodle XSS" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2004 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_moodle_cms_detect.sc", "cross_site_scripting.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Moodle/Version" );
	script_tag( name: "summary", value: "The remote host is using Moodle, a course management system (CMS).
There is a bug in this software that makes it vulnerable to cross
site scripting attacks.

An attacker may use this bug to steal the credentials of the
legitimate users of this site." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
 of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
 disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
install = get_kb_item( NASLString( "www/", port, "/moodle" ) );
if(isnull( install )){
	exit( 0 );
}
matches = eregmatch( string: install, pattern: "^(.+) under (/.*)$" );
if(!isnull( matches )){
	loc = matches[2];
	req = http_get( item: NASLString( loc, "/help.php?text=%3Cscript%3Efoo%3C/script%3E" ), port: port );
	r = http_keepalive_send_recv( port: port, data: req );
	if(isnull( r )){
		exit( 0 );
	}
	if(IsMatchRegexp( r, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "<script>foo</script>", string: r )){
		security_message( port );
		exit( 0 );
	}
}

