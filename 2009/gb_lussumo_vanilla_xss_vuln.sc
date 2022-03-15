CPE = "cpe:/a:lussumo:vanilla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800623" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2009-06-04 10:49:28 +0200 (Thu, 04 Jun 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-1845" );
	script_bugtraq_id( 35114 );
	script_name( "Vanilla 'RequestName' Cross-Site Scripting Vulnerability" );
	script_category( ACT_MIXED_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_lussumo_vanilla_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Lussumo/Vanilla/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35234" );
	script_xref( name: "URL", value: "http://gsasec.blogspot.com/2009/05/vanilla-v117-cross-site-scripting.html" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in context of an
  affect site and it result XSS attack." );
	script_tag( name: "affected", value: "Lussumo Vanilla 1.1.7 and prior on all running platform." );
	script_tag( name: "insight", value: "Error is due to improper sanitization of user supplied input
  in the 'RequestName' parameter in '/ajax/updatecheck.php' file." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Lussumo Vanilla and is prone to Cross-Site
  Scripting Vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: FALSE )){
	exit( 0 );
}
ver = infos["version"];
dir = infos["location"];
install = dir;
if(dir == "/"){
	dir = "";
}
if(!safe_checks()){
	url = dir + "/ajax/updatecheck.php?PostBackKey=1&ExtensionKey=1&RequestName=1<script>alert(Exploit-XSS)</script>";
	req = http_get( item: url, port: port );
	res = http_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "Exploit-XSS" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(ver && version_is_less_equal( version: ver, test_version: "1.1.8" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "None", install_path: install );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

