CPE = "cpe:/a:apache:opentaps";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.101024" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2009-04-25 22:17:58 +0200 (Sat, 25 Apr 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Opentaps ERP + CRM Default Credentials" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Christian Eric Edjenguele <christian.edjenguele@owasp.org>" );
	script_family( "Web application abuses" );
	script_dependencies( "remote-detect-Opentaps_ERP_CRM.sc" );
	script_mandatory_keys( "OpentapsERP/installed" );
	script_tag( name: "summary", value: "The remote host is running Opentaps ERP + CRM with default
  credentials." );
	script_tag( name: "solution", value: "Set a strong password for the mentioned accounts." );
	script_tag( name: "impact", value: "This allow an attacker to gain possible administrative access to
  the remote application." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
modules = get_kb_list( "OpentapsERP/" + port + "/modules" );
if(modules){
	credentials = make_array( "1", "1", "2", "2", "admin", "ofbiz", "DemoCustomer", "ofbiz" );
	for username in keys( credentials ) {
		postdata = NASLString( "USERNAME=" + username + "&PASSWORD=" + credentials[username] );
		postlen = strlen( postdata );
		modules = sort( modules );
		host = http_host_name( port: port );
		for module in modules {
			url = module + "/control/login";
			req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", postlen, "\\r\\n", "Referer: http://", host, url, "\\r\\n", "Host: ", host, "\\r\\n\\r\\n", postdata );
			res = http_keepalive_send_recv( port: port, data: req );
			if(!res){
				continue;
			}
			welcomeMsg = egrep( pattern: "(Welcome(&nbsp;| | <br />)(THE(&nbsp;| )ADMIN|Limited Administrator|Demo Customer)|THE PRIVILEGED ADMINISTRATOR|/control/logout\">Logout</a></li>)", string: res );
			if(!welcomeMsg){
				continue;
			}
			VULN = TRUE;
			report += username + ":" + credentials[username] + ":" + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + "\n";
		}
	}
	if(VULN){
		report = "It was possible to login with default credentials at the following modules (username:password:url):\n\n" + report;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

