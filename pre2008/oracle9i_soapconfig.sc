CPE = "cpe:/a:oracle:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11224" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 4290 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2002-0568" );
	script_name( "Oracle 9iAS SOAP configuration file retrieval" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Javier Fernandez-Sanguino" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_oracle_app_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "oracle/http_server/detected" );
	script_xref( name: "URL", value: "http://otn.oracle.com/deploy/security/pdf/ojvm_alert.pdf" );
	script_xref( name: "URL", value: "http://www.cert.org/advisories/CA-2002-08.html" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/476619" );
	script_xref( name: "URL", value: "http://www.nextgenss.com/papers/hpoas.pdf" );
	script_tag( name: "solution", value: "Modify the file permissions so that the web server process
  cannot retrieve it. Note however that if the XSQLServlet is present
  it might bypass filesystem restrictions." );
	script_tag( name: "summary", value: "In a default installation of Oracle 9iAS v.1.0.2.2.1, it is possible to
  access some configuration files. These file includes detailed
  information on how the product was installed in the server
  including where the SOAP provider and service manager are located
  as well as administrative URLs to access them. They might also
  contain sensitive information (usernames and passwords for database
  access)." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
configs = make_list( "/soapdocs/webapps/soap/WEB-INF/config/soapConfig.xml" );
VULN = FALSE;
report = "The following SOAP configuration files can be accessed directly:\n";
for config in configs {
	req = http_get( item: config, port: port );
	r = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(isnull( r )){
		exit( 0 );
	}
	if(ContainsString( r, "SOAP configuration file" )){
		report += "\n" + http_report_vuln_url( port: port, url: config, url_only: TRUE );
		VULN = TRUE;
	}
}
if(VULN){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

