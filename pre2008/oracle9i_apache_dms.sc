CPE = "cpe:/a:oracle:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10848" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 4293 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2002-0563" );
	script_name( "Oracle 9iAS Dynamic Monitoring Services" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2002 Matt Moore" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_oracle_app_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "oracle/http_server/detected" );
	script_tag( name: "solution", value: "Edit httpd.conf to restrict access to /dms0." );
	script_tag( name: "summary", value: "In a default installation of Oracle 9iAS, it is possible to access the
  Dynamic Monitoring Services pages anonymously. Access to these pages should be restricted." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "Mitigation" );
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
url = "/dms0";
req = http_get( item: url, port: port );
res = http_send_recv( port: port, data: req );
if(!res){
	exit( 0 );
}
if(ContainsString( res, "DMSDUMP version" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

