if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113109" );
	script_version( "2021-06-22T11:00:29+0000" );
	script_tag( name: "last_modification", value: "2021-06-22 11:00:29 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-13 10:50:30 +0100 (Tue, 13 Feb 2018)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-26 18:52:00 +0000 (Mon, 26 Feb 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_cve_id( "CVE-2018-6844" );
	script_name( "MyBB 1.8.14 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_mybb_detect.sc" );
	script_mandatory_keys( "MyBB/installed" );
	script_tag( name: "summary", value: "MyBB is prone to an XSS vulnerability." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "XSS Vulnerability via the Title or Description field on the Edit Forum screen." );
	script_tag( name: "affected", value: "MyBB through version 1.8.14." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://websecnerd.blogspot.de/2018/02/mybb-forum-1.html" );
	script_xref( name: "URL", value: "https://blog.mybb.com/category/updates/" );
	exit( 0 );
}
CPE = "cpe:/a:mybb:mybb";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "1.8.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

