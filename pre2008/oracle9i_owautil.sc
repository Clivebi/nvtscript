CPE = "cpe:/a:oracle:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11225" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 4294 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2002-0560" );
	script_name( "Oracle 9iAS OWA UTIL access" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Javier Fernandez-Sanguino" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_oracle_app_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "oracle/http_server/detected" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/307835" );
	script_xref( name: "URL", value: "http://www.cert.org/advisories/CA-2002-08.html" );
	script_xref( name: "URL", value: "http://otn.oracle.co.kr/docs/oracle78/was3x/was301/cart/psutil.htm" );
	script_xref( name: "URL", value: "http://www.nextgenss.com/papers/hpoas.pdf" );
	script_xref( name: "URL", value: "http://otn.oracle.com/deploy/security/pdf/ias_modplsql_alert.pdf" );
	script_tag( name: "summary", value: "Oracle 9iAS can provide access to the PL/SQL application OWA_UTIL that
  provides web access to some stored procedures." );
	script_tag( name: "impact", value: "These procuedures, without authentication, can allow users to access
  sensitive information such as source code of applications, user credentials to other
  database servers and run arbitrary SQL queries on servers accessed by the application
  server." );
	script_tag( name: "solution", value: "Apply the appropriate patch listed
  in the references.

  Details how you can restrict unauthenticated access to procedures
  using the exclusion_list parameter in the PL/SQL gateway configuration file:
  /Apache/modplsql/cfg/wdbsvr.app." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
owas = make_list( "/ows-bin/owa/owa_util.signature",
	 "/ows-bin/owa/owa_util%2esignature",
	 "/ows-bin/owa/owa%5futil.signature",
	 "/ows-bin/owa/owa%5futil.signature",
	 "/ows-bin/owa/%20owa_util.signature",
	 "/ows-bin/owa/%0aowa_util.signature",
	 "/ows-bin/owa/%08owa_util.signature",
	 "/ows-bin/owa/owa_util.showsource",
	 "/ows-bin/owa/owa_util.cellsprint",
	 "/ows-bin/owa/owa_util.tableprint",
	 "/ows-bin/owa/owa_util.listprint",
	 "/ows-bin/owa/owa_util.show_query_columns" );
VULN = FALSE;
report = "Access to OWA_UTIL is possible through the following URLs:\n";
for owa in owas {
	req = http_get( item: owa, port: port );
	r = http_keepalive_send_recv( port: port, data: req );
	if(r == NULL){
		exit( 0 );
	}
	if(ContainsString( r, "This page was produced by the PL/SQL Web ToolKit" ) || ContainsString( r, "DAD name:" ) || ContainsString( r, "PATH_INFO=/ows-bin/owa/" )){
		VULN = TRUE;
		report += "\n" + http_report_vuln_url( port: port, url: owa, url_only: TRUE );
	}
}
if(VULN){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

