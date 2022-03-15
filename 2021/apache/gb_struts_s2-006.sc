CPE = "cpe:/a:apache:struts";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117661" );
	script_version( "2021-09-15T09:21:17+0000" );
	script_cve_id( "CVE-2011-1772" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-15 09:21:17 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-14 12:29:06 +0000 (Tue, 14 Sep 2021)" );
	script_name( "Apache Struts Security Update (S2-006) - Version Check" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_dependencies( "gb_apache_struts_consolidation.sc" );
	script_mandatory_keys( "apache/struts/detected" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-006" );
	script_xref( name: "Advisory-ID", value: "S2-006" );
	script_tag( name: "summary", value: "The remote host is missing a security update for Apache Struts
  announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Apache Struts 2.0.0 through 2.2.1.1." );
	script_tag( name: "solution", value: "Update to version 2.2.3 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(version_in_range( version: version, test_version: "2.0.0", test_version2: "2.2.1.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

