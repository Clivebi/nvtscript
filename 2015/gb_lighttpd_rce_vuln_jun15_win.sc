CPE = "cpe:/a:lighttpd:lighttpd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805591" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_cve_id( "CVE-2015-3200" );
	script_bugtraq_id( 74813 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2015-06-19 09:50:40 +0530 (Fri, 19 Jun 2015)" );
	script_name( "Lighttpd 'http_auth.c' Remote Code Execution Vulnerability - June15 (Windows)" );
	script_tag( name: "summary", value: "This host is running Lighttpd and is prone to
  remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Check if the vulnerable version of Lighttpd
  is installed or not." );
	script_tag( name: "insight", value: "The flaw exists due to an error in
  'http_auth.c' which does not properly validate user-supplied input." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to execute arbitrary code on affected system." );
	script_tag( name: "affected", value: "Lighttpd version before 1.4.36 on windows." );
	script_tag( name: "solution", value: "Upgrade to Lighttpd 1.4.36 or later." );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1032405" );
	script_xref( name: "URL", value: "http://jaanuskp.blogspot.in/2015/05/cve-2015-3200.html" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_dependencies( "sw_lighttpd_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "lighttpd/installed", "Host/runs_windows" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.lighttpd.net" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "1.4.36" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.4.36" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

