if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802253" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)" );
	script_bugtraq_id( 43035 );
	script_cve_id( "CVE-2010-4910" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "ColdGen ColdCalendar 'EventID' SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41333" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/61637" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14932/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/93557/coldcalendar-sql.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause SQL Injection
  attack and gain sensitive information." );
	script_tag( name: "affected", value: "ColdGen ColdCalendar version 2.06." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input
  via the 'EventID' parameter in index.cfm, which allows attacker to manipulate
  SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running ColdGen ColdCalendar and is prone to SQL
  injection vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/coldcal", "/coldcalendar", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.cfm", port: port );
	if(ContainsString( res, "<title>ColdCalendar" )){
		url = dir + "/index.cfm?fuseaction=ViewEventDetails&EventID=1+and+1";
		if(http_vuln_check( port: port, url: url, pattern: "Error Executing Database " + "Query", extra_check: make_list( "SELECT *",
			 "WHERE EventID = 1 and 1" ) )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

