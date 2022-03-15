if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108440" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-04-16 15:31:23 +0200 (Mon, 16 Apr 2018)" );
	script_tag( name: "cvss_base", value: "4.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "Cleartext Transmission of Sensitive Information via HTTP" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "webmirror.sc", "DDI_Directory_Scanner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "www/pw_input_field_or_basic_auth/detected" );
	script_xref( name: "URL", value: "https://www.owasp.org/index.php/Top_10_2013-A2-Broken_Authentication_and_Session_Management" );
	script_xref( name: "URL", value: "https://www.owasp.org/index.php/Top_10_2013-A6-Sensitive_Data_Exposure" );
	script_xref( name: "URL", value: "https://cwe.mitre.org/data/definitions/319.html" );
	script_tag( name: "summary", value: "The host / application transmits sensitive information (username, passwords) in
  cleartext via HTTP." );
	script_tag( name: "vuldetect", value: "Evaluate previous collected information and check if the host / application is not
  enforcing the transmission of sensitive data via an encrypted SSL/TLS connection.

  The script is currently checking the following:

  - HTTP Basic Authentication (Basic Auth)

  - HTTP Forms (e.g. Login) with input field of type 'password'" );
	script_tag( name: "impact", value: "An attacker could use this situation to compromise or eavesdrop on the
  HTTP communication between the client and the server using a man-in-the-middle attack to get access to
  sensitive data like usernames or passwords." );
	script_tag( name: "affected", value: "Hosts / applications which doesn't enforce the transmission of sensitive data via an
  encrypted SSL/TLS connection." );
	script_tag( name: "solution", value: "Enforce the transmission of sensitive data via an encrypted SSL/TLS connection.
  Additionally make sure the host / application is redirecting all users to the secured SSL/TLS connection before
  allowing to input sensitive data into the mentioned functions." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
inputFieldReport = "The following input fields where identified (URL:input name):\n";
basicAuthReport = "The following URLs requires Basic Authentication (URL:realm name):\n";
port = http_get_port( default: 80 );
if(get_port_transport( port ) > ENCAPS_IP){
	exit( 99 );
}
host = http_host_name( dont_add_port: TRUE );
inputFieldList = get_kb_list( "www/" + host + "/" + port + "/content/pw_input_field/*" );
if(!isnull( inputFieldList )){
	inputFieldList = sort( inputFieldList );
	for inputField in inputFieldList {
		INPUT_VULN = TRUE;
		inputFieldReport += "\n" + inputField;
	}
}
basicAuthList = get_kb_list( "www/" + host + "/" + port + "/content/basic_auth/*" );
if(!isnull( basicAuthList )){
	basicAuthList = sort( basicAuthList );
	for basicAuth in basicAuthList {
		BASIC_VULN = TRUE;
		basicAuthReport += "\n" + basicAuth;
	}
}
if(INPUT_VULN || BASIC_VULN){
	if(INPUT_VULN){
		report = inputFieldReport;
	}
	if(INPUT_VULN && BASIC_VULN){
		report += "\n\n";
	}
	if(BASIC_VULN){
		report = basicAuthReport;
	}
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

