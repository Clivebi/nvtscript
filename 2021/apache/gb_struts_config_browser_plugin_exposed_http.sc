if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117679" );
	script_version( "2021-09-17T07:29:47+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 07:29:47 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-16 10:49:32 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "Apache Struts Config Browser Plugin Exposed (S2-043) - Active Check" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The remote host is exposing the Apache Struts Config Browser
  Plugin via HTTP." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "Usage of the Config Browser Plugin in a production environment
  can lead to exposing vulnerable information of the application." );
	script_tag( name: "affected", value: "Any Apache Struts 2 version exposing the Config Browser Plugin
  to the public / using it in a production environment." );
	script_tag( name: "solution", value: "Please read the linked Security guideline and restrict access
  to the Config Browser Plugin or do not use in a production environment." );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-043" );
	script_xref( name: "Advisory-ID", value: "S2-043" );
	script_xref( name: "URL", value: "http://struts.apache.org/security/#restrict-access-to-the-config-browser-plugin" );
	script_xref( name: "URL", value: "https://struts.apache.org/plugins/config-browser/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("list_array_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
VULN = FALSE;
report = "The Apache Struts Config Browser Plugin was found to be enabled / exposed on the following URL(s):\n";
for dir in nasl_make_list_unique( "/", "/struts", "/struts2-showcase", "/struts2-blank", "/struts2-basic", "/struts2-mailreader", "/struts2-portlet", "/struts2-rest-showcase", "/struts-cookbook", "/struts-examples", "/starter", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for url in make_list( dir + "/config-browser/index.action",
		 dir + "/config-browser/index" ) {
		res = http_get_cache( item: url, port: port );
		if(!res || !IsMatchRegexp( res, "HTTP/1\\.[01] 200" )){
			continue;
		}
		if(ContainsString( res, "Struts Configuration Browser > " )){
			VULN = TRUE;
			report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			break;
		}
	}
}
if(VULN){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

