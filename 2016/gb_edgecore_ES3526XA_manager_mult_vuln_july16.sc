CPE = "cpe:/o:edgecore:es3526xa_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808238" );
	script_version( "2020-10-06T14:10:09+0000" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-06 14:10:09 +0000 (Tue, 06 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-06-27 15:50:17 +0530 (Mon, 27 Jun 2016)" );
	script_name( "EdgeCore ES3526XA Manager Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_edgecore_ES3526XA_manager_remote_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "EdgeCore/ES3526XA/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2016/Jun/62" );
	script_tag( name: "summary", value: "This host is installed with EdgeCore
  ES3526XA Manager and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to bypass authentication or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - No CSRF Token is generated per page and / or per (sensitive) function

  - An improper access control mechanism so that any functions can be performed
  by directly calling the function URL (GET/POST) without any authentication

  - It is possible to login with default credential admin:admin or guest:guest,
  and mandatory password change is not enforced by the application" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers silent execution of unauthorized actions on the device such as
  password change, configuration parameter changes, to bypass authentication
  and to perform any administrative functions such as add, update, delete users." );
	script_tag( name: "affected", value: "EdgeCore - Layer2+ Fast Ethernet Standalone Switch ES3526XA Manager.

  Please see the referenced link for the affected switch information." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
buf = http_get_cache( item: "/", port: port );
if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 401" )){
	exit( 0 );
}
for credential in make_list( "admin:admin",
	 "guest:guest" ) {
	userpass = base64( str: credential );
	req = "GET / HTTP/1.1\r\n" + "Authorization: Basic " + userpass + "\r\n" + "\r\n";
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "cluster_info" ) && ContainsString( buf, "cluster_main.htm" ) && ContainsString( buf, "cluster_link.htm" )){
		report = "It was possible to login using the following credentials:\n\n" + credential;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

