CPE = "cpe:/a:apache:activemq";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108253" );
	script_version( "2020-04-29T15:01:10+0000" );
	script_name( "Apache ActiveMQ Web Console Default / No Credentials" );
	script_tag( name: "last_modification", value: "2020-04-29 15:01:10 +0000 (Wed, 29 Apr 2020)" );
	script_tag( name: "creation_date", value: "2017-10-13 10:31:00 +0200 (Fri, 13 Oct 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_apache_activemq_consolidation.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 8161 );
	script_mandatory_keys( "ActiveMQ/Web/auth_or_unprotected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://activemq.apache.org/web-console.html" );
	script_tag( name: "summary", value: "The Apache ActiveMQ Web Console is unprotected or prone
  to a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information." );
	script_tag( name: "solution", value: "Change or set the password." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
vuln = FALSE;
report = "It was possible to access the Apache ActiveMQ Web Console at:";
host = http_host_name( dont_add_port: TRUE );
unprotectedUrls = get_kb_list( "www/" + host + "/" + port + "/ActiveMQ/Web/unprotected" );
authRequireUrls = get_kb_list( "www/" + host + "/" + port + "/ActiveMQ/Web/auth_required" );
if(!isnull( unprotectedUrls )){
	unprotectedUrls = sort( unprotectedUrls );
	for url in unprotectedUrls {
		report += "\n\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + " without any username/password";
		vuln = TRUE;
	}
}
if(!isnull( authRequireUrls )){
	credentials = make_list( "admin:admin",
		 "user:user" );
	authRequireUrls = sort( authRequireUrls );
	for url in authRequireUrls {
		for credential in credentials {
			user_pass = split( buffer: credential, sep: ":", keep: FALSE );
			user = chomp( user_pass[0] );
			pass = chomp( user_pass[1] );
			userpass = NASLString( user, ":", pass );
			userpass64 = base64( str: userpass );
			req = http_get_req( port: port, url: url, add_headers: make_array( "Authorization", "Basic " + userpass64 ) );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			if(IsMatchRegexp( res, "HTTP/1\\.[01] 200" ) && egrep( pattern: "(Apache )?ActiveMQ( Console)?</title>", string: res, icase: TRUE )){
				report += "\n\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + " using user \"" + user + "\" with password \"" + pass + "\"";
				vuln = TRUE;
			}
		}
	}
}
if(vuln){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

