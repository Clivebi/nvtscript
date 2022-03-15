CPE = "cpe:/a:textpattern:textpattern";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801442" );
	script_version( "2021-07-06T11:33:52+0000" );
	script_tag( name: "last_modification", value: "2021-07-06 11:33:52 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2010-11-11 07:48:04 +0100 (Thu, 11 Nov 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-3205" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Textpattern CMS 'index.php' Remote File Inclusion Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_textpattern_cms_http_detect.sc" );
	script_mandatory_keys( "textpattern_cms/detected" );
	script_tag( name: "summary", value: "Textpattern CMS is prone to a remote file inclusion
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error in 'index.php', which is not
  properly sanitizing user-supplied data via 'inc' parameter. This allows an attacker to include
  arbitrary files." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  code on the vulnerable Web server." );
	script_tag( name: "affected", value: "Textpattern CMS version 4.2.0 and prior." );
	script_tag( name: "solution", value: "Update to version 4.3.0 or later." );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/61475" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14823/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/1008-exploits/textpattern-rfi.txt" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
if(version_is_less( version: vers, test_version: "4.3.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.3.0", install_path: infos["location"] );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

