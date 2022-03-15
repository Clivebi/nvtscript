CPE = "cpe:/a:httpfilesever:hfs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806813" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_cve_id( "CVE-2014-7226" );
	script_bugtraq_id( 70216 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-01-05 19:14:20 +0530 (Tue, 05 Jan 2016)" );
	script_name( "HTTP File Server Remote Command Execution Vulnerability-01 Jan16" );
	script_tag( name: "summary", value: "This host is running HTTP File Server
  and is prone to remote command execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the application does not
  properly validate uft-8 broken byte representation" );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to execute arbitrary code by uploading a file with certain invalid
  UTF-8 byte sequences that are interpreted as executable macro symbols." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "affected", value: "HttpFileServer version 2.3c and prior." );
	script_tag( name: "solution", value: "Update to version 2.3d or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/128532" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_http_file_server_detect.sc" );
	script_mandatory_keys( "hfs/Installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://www.rejetto.com/hfs" );
	exit( 0 );
}
require("http_func.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!hfsPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!hfsVer = get_app_version( cpe: CPE, port: hfsPort )){
	exit( 0 );
}
if(version_is_less( version: hfsVer, test_version: "2.3d" )){
	report = "Installed Version: " + hfsVer + "\n" + "Fixed Version: 2.3d" + "\n";
	security_message( port: hfsPort, data: report );
	exit( 0 );
}

