CPE = "cpe:/a:nghttp2:nghttp2";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106172" );
	script_version( "2020-11-17T16:33:29+0000" );
	script_tag( name: "last_modification", value: "2020-11-17 16:33:29 +0000 (Tue, 17 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-08-08 11:13:25 +0700 (Mon, 08 Aug 2016)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "nghttp2 < 1.7.0 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_nghttp2_detect.sc" );
	script_mandatory_keys( "nghttp2/detected" );
	script_tag( name: "summary", value: "nghttp2 is prone to a Denial-of-Service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "nghttpd is prone to a remote DoS attack. A remote attacker could
  exploit this issue by sending a crafted request that will induce a dependency cycle, causing the
  server to enter an infinite loop." );
	script_tag( name: "impact", value: "A remote attacker may cause a DoS condition." );
	script_tag( name: "affected", value: "Version prior to 1.7.0." );
	script_tag( name: "solution", value: "Upgrade to Version 1.7.0 or later." );
	script_xref( name: "URL", value: "http://www.imperva.com/docs/Imperva_HII_HTTP2.pdf" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.7.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.7.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

