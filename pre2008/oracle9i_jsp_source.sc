CPE = "cpe:/a:oracle:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10852" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 4034 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2002-0562" );
	script_name( "Oracle 9iAS Jsp Source File Reading" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2002 Matt Moore" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_oracle_app_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "oracle/http_server/detected" );
	script_xref( name: "URL", value: "http://wwww.nextgenss.com/advisories/orajsa.txt" );
	script_tag( name: "solution", value: "Edit httpd.conf to disallow access to the _pages folder." );
	script_tag( name: "summary", value: "In a default installation of Oracle 9iAS it is possible to
  read the source of JSP files." );
	script_tag( name: "insight", value: "When a JSP is requested it is compiled 'on the fly' and the
  resulting HTML page is returned to the user. Oracle 9iAS uses a folder to hold the intermediate
  files during compilation. These files are created in the same folder in which the .JSP page resides.
  Hence, it is possible to access the .java and compiled .class files for a given JSP page." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
req = http_get( item: "/demo/ojspext/events/index.jsp", port: port );
res = http_send_recv( port: port, data: req );
if(res && ContainsString( res, "This page has been accessed" )){
	url = "/demo/ojspext/events/_pages/_demo/_ojspext/_events/_index.java";
	req = http_get( item: url, port: port );
	res = http_send_recv( port: port, data: req );
	if(res && ContainsString( res, "import oracle.jsp.runtime.*" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

