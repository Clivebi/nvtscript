CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103550" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_cve_id( "CVE-2010-4094", "CVE-2009-3548", "CVE-2009-4189", "CVE-2009-3099", "CVE-2009-3843", "CVE-2009-4188", "CVE-2010-0557" );
	script_bugtraq_id( 44172, 36954, 79264, 79351, 37086, 36258, 38084 );
	script_name( "Apache Tomcat Manager/Host Manager/Server Status Default/Hardcoded Credentials" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2012-08-22 17:19:15 +0200 (Wed, 22 Aug 2012)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "apache/tomcat/http/detected", "ApacheTomcat/auth_required" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://www.zerodayinitiative.com/advisories/ZDI-10-214/" );
	script_xref( name: "URL", value: "https://www.zerodayinitiative.com/advisories/ZDI-09-085/" );
	script_tag( name: "solution", value: "Change the password to a strong one or remove the user from tomcat-users.xml." );
	script_tag( name: "summary", value: "The Apache Tomcat Manager/Host Manager/Server Status is using default or known
  hardcoded credentials." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to upload and execute arbitrary
  code, which will facilitate a complete compromise of the affected computer." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_timeout( 600 );
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
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
credentials = make_list( "admin:admin",
	 "admin:changethis",
	 "admin:password",
	 "admin:Password1",
	 "admin:password1",
	 "admin:vagrant",
	 "both:tomcat",
	 "manager:manager",
	 "password:password",
	 "role:changethis",
	 "role1:role1",
	 "role1:tomcat",
	 "role1:tomcat7",
	 "root:changethis",
	 "root:password",
	 "root:Password1",
	 "root:password1",
	 "root:r00t",
	 "root:root",
	 "root:toor",
	 "scott:tiger",
	 "tomcat:admin",
	 "tomcat:changethis",
	 "tomcat:j5Brn9",
	 "tomcat:none",
	 "tomcat:password",
	 "tomcat:Password1",
	 "tomcat:password1",
	 "tomcat:tomcat",
	 "ADMIN:ADMIN",
	 "admin:none",
	 "admin:tomcat",
	 "ovwebusr:OvW*busr1",
	 "j2deployer:j2deployer",
	 "tomcat:s3cret",
	 "cxsdk:kdsxc",
	 "xampp:xampp",
	 "QCC:QLogic66",
	 "root:owaspbwa",
	 "fhir:FHIRDefaultPassword" );
host = http_host_name( dont_add_port: TRUE );
vuln = FALSE;
report = "";
authRequireUrls = get_kb_list( "www/" + host + "/" + port + "/ApacheTomcat/auth_required" );
if(isnull( authRequireUrls )){
	exit( 0 );
}
authRequireUrls = sort( authRequireUrls );
useragent = http_get_user_agent();
host = http_host_name( port: port );
for url in authRequireUrls {
	for credential in credentials {
		user_pass = split( buffer: credential, sep: ":", keep: FALSE );
		user = chomp( user_pass[0] );
		pass = chomp( user_pass[1] );
		if(tolower( pass ) == "none"){
			pass = "";
		}
		userpass = NASLString( user, ":", pass );
		userpass64 = base64( str: userpass );
		req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Authorization: Basic ", userpass64, "\\r\\n", "\\r\\n" );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if( IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "Tomcat Web Application Manager" ) ){
			report += "It was possible to login into the Tomcat Manager at " + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + " using user \"" + user + "\" with password \"" + pass + "\"\n\n";
			vuln = TRUE;
		}
		else {
			if( IsMatchRegexp( res, "^HTTP/1\\.[01]" ) && ContainsString( res, "Tomcat Virtual Host Manager" ) ){
				report += "It was possible to login into the Tomcat Host Manager at " + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + " using user \"" + user + "\" with password \"" + pass + "\"\n\n";
				vuln = TRUE;
			}
			else {
				if(IsMatchRegexp( res, "^HTTP/1\\.[01]" ) && ContainsString( res, "Server Status" ) && ContainsString( res, "Complete Server Status" )){
					report += "It was possible to login into the Tomcat Server Status at " + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + " using user \"" + user + "\" with password \"" + pass + "\"\n\n";
					vuln = TRUE;
				}
			}
		}
	}
}
if(vuln){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

