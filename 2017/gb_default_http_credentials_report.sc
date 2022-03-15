if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103240" );
	script_version( "2021-01-21T10:06:42+0000" );
	script_tag( name: "last_modification", value: "2021-01-21 10:06:42 +0000 (Thu, 21 Jan 2021)" );
	script_tag( name: "creation_date", value: "2017-01-06 13:47:00 +0100 (Fri, 06 Jan 2017)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_name( "HTTP Brute Force Logins With Default Credentials Reporting" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_END );
	script_family( "Brute force attacks" );
	script_dependencies( "default_http_auth_credentials.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "default_http_auth_credentials/started" );
	script_tag( name: "summary", value: "It was possible to login into the remote Web Application using default credentials.

  As the VT 'HTTP Brute Force Logins With Default Credentials' (OID: 1.3.6.1.4.1.25623.1.0.108041) might run into a
  timeout the actual reporting of this vulnerability takes place in this VT instead." );
	script_tag( name: "solution", value: "Change the password as soon as possible." );
	script_tag( name: "vuldetect", value: "Reports default credentials detected by the VT 'HTTP Brute Force Logins With Default Credentials'
  (OID: 1.3.6.1.4.1.25623.1.0.108041)." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
credentials = get_kb_list( "default_http_auth_credentials/" + host + "/" + port + "/credentials" );
if(!isnull( credentials )){
	report = "It was possible to login with the following credentials (<URL>:<User>:<Password>:<HTTP status code>)\n\n";
	credentials = sort( credentials );
	for credential in credentials {
		url_user_pass = split( buffer: credential, sep: "#-----#", keep: FALSE );
		report += http_report_vuln_url( port: port, url: url_user_pass[0], url_only: TRUE ) + ":" + url_user_pass[1] + "\n";
		vuln = TRUE;
	}
}
if(vuln){
	count = get_kb_item( "default_http_auth_credentials/" + host + "/" + port + "/too_many_logins" );
	if(count){
		report += "\nRemote host accept more than " + count + " logins. This could indicate some error or some \"broken\" web application.\nScanner stops testing for default logins at this point.";
		log_message( port: port, data: report );
		exit( 0 );
	}
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

