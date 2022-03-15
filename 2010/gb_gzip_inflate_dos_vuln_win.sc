if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800452" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-02-04 12:53:38 +0100 (Thu, 04 Feb 2010)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-2624" );
	script_bugtraq_id( 37888 );
	script_name( "GZip 'huft_build()' in 'inflate.c' Input Validation Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/0185" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=514711" );
	script_xref( name: "URL", value: "http://git.savannah.gnu.org/cgit/gzip.git/commit/?id=39a362ae9d9b007473381dba5032f4dfc1744cf2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_gzip_detect_win.sc" );
	script_mandatory_keys( "GZip/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could result in Denial of service (application
  crash or infinite loop) or possibly execute arbitrary code via a crafted archive." );
	script_tag( name: "affected", value: "GZip version prior to 1.3.13 on Windows." );
	script_tag( name: "insight", value: "The flaw is due to error in 'huft_build()' function in 'inflate.c', creates
  a hufts table that is too small." );
	script_tag( name: "summary", value: "This host is installed with GZip and is prone to Input Validation
  Vulnerability" );
	script_tag( name: "solution", value: "Update to GZip version 1.3.13 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:gnu:gzip";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "1.3.13" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.13", install_path: location );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

