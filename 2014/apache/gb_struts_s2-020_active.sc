CPE = "cpe:/a:apache:struts";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105910" );
	script_version( "2021-09-15T09:21:17+0000" );
	script_bugtraq_id( 65999 );
	script_cve_id( "CVE-2014-0094" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-15 09:21:17 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2014-05-14 13:53:39 +0700 (Wed, 14 May 2014)" );
	script_name( "Apache Struts Security Update (S2-020) - Active Check" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_struts_consolidation.sc", "webmirror.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "apache/struts/http/detected" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-020" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/65999" );
	script_xref( name: "Advisory-ID", value: "S2-020" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-058" );
	script_xref( name: "Advisory-ID", value: "S2-058" );
	script_tag( name: "summary", value: "ClassLoader Manipulation allows remote attackers to execute
  arbitrary Java code." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "The ParametersInterceptor allows remote attackers to manipulate
  the ClassLoader via the class parameter, which is passed to the getClass method." );
	script_tag( name: "impact", value: "A remote attacker can execute arbitrary Java code via crafted
  parameters." );
	script_tag( name: "affected", value: "Apache Struts 2.0.0 through 2.3.16.1." );
	script_tag( name: "solution", value: "Update to version 2.3.16.2 or later." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
if(!apps = http_get_kb_cgis( port: port, host: host )){
	exit( 0 );
}
for app in apps {
	if(ContainsString( app, ".action" )){
		end = strstr( app, " " );
		dir = app - end;
		url = dir + "?Class.classLoader.resources.dirContext.cacheObjectMaxSize=x";
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(ContainsString( res, "No result defined for action" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

