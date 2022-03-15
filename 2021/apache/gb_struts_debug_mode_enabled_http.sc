if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117689" );
	script_version( "2021-09-28T06:32:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-28 06:32:28 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-21 13:11:29 +0000 (Tue, 21 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "Apache Struts Debug Mode Enabled - Active Check" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "gb_vmware_vcenter_server_http_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "www/action_jsp_do" );
	script_tag( name: "summary", value: "The remote host is running an Apache Struts application with
  enabled debug mode." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "Usage of debug mode in a production environment can lead to
  exposing vulnerable information of the application." );
	script_tag( name: "affected", value: "Any Apache Struts 2 application exposing the debug mode output
  to the public / using it in a production environment." );
	script_tag( name: "solution", value: "Disable the debug mode in a production environment." );
	script_xref( name: "URL", value: "https://struts.apache.org/core-developers/debugging.html" );
	script_xref( name: "URL", value: "https://struts.apache.org/core-developers/debugging-interceptor.html" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("list_array_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
host = http_host_name( dont_add_port: TRUE );
urls = make_list();
for ext in make_list( "action",
	 "do",
	 "jsp" ) {
	exts = http_get_kb_file_extensions( port: port, host: host, ext: ext );
	if(exts && is_array( exts )){
		urls = make_list( urls,
			 exts );
	}
}
if(get_kb_item( "vmware/vcenter/server/http/detected" )){
	urls = nasl_make_list_unique( "/statsreport/", urls );
}
x = 0;
vuln = FALSE;
max_items = 10;
cur_items = 0;
report = "The remote host has the debug mode enabled for the following URL(s): (output limited to " + max_items + " entries)\n";
for url in urls {
	x++;
	url += "?debug=xml";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(egrep( pattern: "^\\s*<debug>", string: res, icase: FALSE ) && egrep( pattern: "^\\s*<struts\\.actionMapping>", string: res, icase: FALSE )){
		vuln = TRUE;
		cur_items++;
		report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		if(cur_items >= max_items){
			break;
		}
	}
	if(x > 25){
		break;
	}
}
if(vuln){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

