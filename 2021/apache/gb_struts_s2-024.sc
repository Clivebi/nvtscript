CPE = "cpe:/a:apache:struts";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117290" );
	script_version( "2021-09-15T09:21:17+0000" );
	script_cve_id( "CVE-2015-1831" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-15 09:21:17 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-04-06 13:58:41 +0000 (Tue, 06 Apr 2021)" );
	script_name( "Apache Struts Security Update (S2-024)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_dependencies( "gb_apache_struts_consolidation.sc" );
	script_mandatory_keys( "apache/struts/detected" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-024" );
	script_xref( name: "Advisory-ID", value: "S2-024" );
	script_tag( name: "summary", value: "Apache Struts is prone to an unspecified
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the
  target host." );
	script_tag( name: "insight", value: "Wrong default exclude patterns were introduced in
  version 2.3.20 of Struts, if default settings are used, the attacker can compromise
  internal application's state." );
	script_tag( name: "affected", value: "Apache Struts 2.3.20." );
	script_tag( name: "solution", value: "Update to version 2.3.20.1 or later." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_equal( version: version, test_version: "2.3.20" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.3.20.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

