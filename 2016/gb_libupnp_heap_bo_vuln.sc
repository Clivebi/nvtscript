CPE = "cpe:/a:libupnp_project:libupnp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106377" );
	script_version( "2020-06-08T12:04:49+0000" );
	script_tag( name: "last_modification", value: "2020-06-08 12:04:49 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-11-04 14:37:33 +0700 (Fri, 04 Nov 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2016-8863" );
	script_name( "libupnp Heap Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_libupnp_consolidation.sc" );
	script_mandatory_keys( "libupnp/detected" );
	script_xref( name: "URL", value: "https://sourceforge.net/p/pupnp/bugs/133/" );
	script_xref( name: "URL", value: "http://pupnp.sourceforge.net/ChangeLog" );
	script_tag( name: "summary", value: "libupnp is prone to a heap buffer overflow vulnerability" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "There is a heap buffer overflow vulnerability in the create_url_list
  function in upnp/src/gena/gena_device.c." );
	script_tag( name: "impact", value: "An unauthenticated attacker may conduct a denial of service attack." );
	script_tag( name: "solution", value: "Upgrade to version 1.6.21 or later." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_proto( cpe: CPE, port: port )){
	exit( 0 );
}
version = infos["version"];
proto = infos["proto"];
if(version_in_range( version: version, test_version: "1.6", test_version2: "1.6.20" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.6.21" );
	security_message( port: port, data: report, proto: proto );
	exit( 0 );
}
exit( 99 );

