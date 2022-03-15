if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117574" );
	script_version( "2021-10-06T04:47:56+0000" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2021-07-22 12:59:06 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-07 15:43:00 +0000 (Wed, 07 Nov 2018)" );
	script_cve_id( "CVE-2014-3744", "CVE-2015-3337", "CVE-2017-1000028", "CVE-2017-14849", "CVE-2017-16877", "CVE-2017-6190", "CVE-2018-10822", "CVE-2018-1271", "CVE-2018-16288", "CVE-2018-16836", "CVE-2018-3714", "CVE-2019-12314", "CVE-2019-14322", "CVE-2019-3799", "CVE-2020-35736", "CVE-2020-5405", "CVE-2021-23241", "CVE-2021-3223", "CVE-2021-40960", "CVE-2021-41773" );
	script_name( "Generic HTTP Directory Traversal (HTTP Web Dirs Check)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning", "global_settings/disable_generic_webapp_scanning" );
	script_xref( name: "URL", value: "https://owasp.org/www-community/attacks/Path_Traversal" );
	script_tag( name: "summary", value: "Generic check for HTTP directory traversal vulnerabilities on
  each HTTP directory.

  NOTE: Please enable 'Enable generic web application scanning' within the VT 'Global variable
  settings' (OID: 1.3.6.1.4.1.25623.1.0.12288) if you want to run this script." );
	script_tag( name: "impact", value: "Successfully exploiting this issue may allow an attacker to
  access paths and directories that should normally not be accessible by a user. This can result in
  effects ranging from disclosure of confidential information to arbitrary code execution." );
	script_tag( name: "affected", value: "The following products are known to be affected by the pattern
  checked in this VT:

  - CVE-2014-3744: st module for Node.js

  - CVE-2015-3337: Elasticsearch

  - CVE-2017-6190 and CVE-2018-10822: D-Link Routers

  - CVE-2017-1000028: Oracle GlassFish Server

  - CVE-2017-14849: Node.js

  - CVE-2017-16877: ZEIT Next.js

  - CVE-2018-1271: Spring MVC

  - CVE-2018-3714: node-srv node module

  - CVE-2018-16288: LG SuperSign CMS

  - CVE-2018-16836: Rubedo

  - CVE-2019-3799 and CVE-2020-5405: Spring Cloud Config

  - CVE-2019-12314: Deltek Maconomy

  - CVE-2019-14322: Pallets Werkzeug

  - CVE-2020-35736: Gate One

  - CVE-2021-3223: Node RED Dashboard

  - CVE-2021-23241: MERCUSYS Mercury X18G

  - CVE-2021-40960: Galera WebTemplate

  - CVE-2021-41773: Apache HTTP Server" );
	script_tag( name: "vuldetect", value: "Sends crafted HTTP requests to the each found directory of the
  remote web server and checks the response." );
	script_tag( name: "solution", value: "Contact the vendor for a solution." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_timeout( 900 );
	exit( 0 );
}
if(get_kb_item( "global_settings/disable_generic_webapp_scanning" )){
	exit( 0 );
}
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
depth = get_kb_item( "global_settings/dir_traversal_depth" );
traversals = traversal_pattern( extra_pattern_list: make_list( "" ), depth: depth );
files = traversal_files();
count = 0;
max_count = 3;
suffixes = make_list( "",
	 "%23vt/test",
	 "%00" );
prefixes = make_list( "",
	 "c:" );
port = http_get_port( default: 80 );
dirs = nasl_make_list_unique( "/loginLess", "/downloads", "/public", "/static", "/spring-mvc-showcase/resources", "/_next", "/signEzUI/playlist/edit/upload", "/node_modules", "/ui_base/js", "/_plugin/head", "/theme/META-INF", "/theme/default/img", "/base_import/static", "/web/static", "/base/static", "/cgi-bin/Maconomy/MaconomyWS.macx1.W_MCS", "/uir", "/GallerySite/filesrc/fotoilan/388/middle/", "/GallerySite/filesrc/", "/GallerySite/", "/cgi-bin", "/test/pathtraversal/master", "/a/b/", http_cgi_dirs( port: port ) );
for dir in dirs {
	if(dir == "/"){
		continue;
	}
	dir_vuln = FALSE;
	for traversal in traversals {
		for pattern in keys( files ) {
			file = files[pattern];
			for suffix in suffixes {
				for prefix in prefixes {
					url = dir + "/" + prefix + traversal + file + suffix;
					req = http_get( port: port, item: url );
					res = http_keepalive_send_recv( port: port, data: req );
					if(egrep( pattern: pattern, string: res, icase: TRUE )){
						count++;
						dir_vuln = TRUE;
						vuln += http_report_vuln_url( port: port, url: url ) + "\n\n";
						vuln += "Request:\n" + chomp( req ) + "\n\nResponse:\n" + chomp( res ) + "\n\n\n";
						break;
					}
				}
				if(count >= max_count || dir_vuln){
					break;
				}
			}
			if(count >= max_count || dir_vuln){
				break;
			}
		}
		if(count >= max_count || dir_vuln){
			break;
		}
	}
	if(count >= max_count){
		break;
	}
}
if(vuln){
	report = "The following affected URL(s) were found (limited to " + max_count + " results):\n\n" + chomp( vuln );
	security_message( port: port, data: report );
}
exit( 0 );

