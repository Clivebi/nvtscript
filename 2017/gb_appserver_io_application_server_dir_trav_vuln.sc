CPE = "cpe:/a:appserver:io";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811268" );
	script_version( "2021-09-14T08:01:37+0000" );
	script_cve_id( "CVE-2015-1847" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-14 08:01:37 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-04 17:00:00 +0000 (Fri, 04 Aug 2017)" );
	script_tag( name: "creation_date", value: "2017-08-02 11:04:18 +0530 (Wed, 02 Aug 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "appserver.io Application Server Directory Traversal Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with appserver.io
  application server and is prone to directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to error in the bundled
  webserver's HTTP parsing library, URI as coming from a web client was not
  normalized correctly." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to traversal movement through the file system of the host without
  the restriction of the configured document root. This allowed for access of
  otherwise inaccessible files through specially crafted HTTP requests." );
	script_tag( name: "affected", value: "appserver.io Application Server before
  version 1.0.3" );
	script_tag( name: "solution", value: "Upgrade to appserver.io version 1.0.3 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://appserver.io/security/2015/03/31/traversal-directory-vulnerability-in-webserver.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_appserver_io_application_server_detect.sc" );
	script_mandatory_keys( "appserver/io/ApplicationServer/ver" );
	script_require_ports( "Services/www", 9080 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!appPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!appVer = get_app_version( cpe: CPE, port: appPort )){
	exit( 0 );
}
if(version_is_less( version: appVer, test_version: "1.0.3" )){
	report = report_fixed_ver( installed_version: appVer, fixed_version: "1.0.3" );
	security_message( data: report, port: appPort );
	exit( 0 );
}
exit( 0 );

