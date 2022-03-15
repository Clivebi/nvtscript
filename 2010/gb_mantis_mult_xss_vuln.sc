CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801603" );
	script_version( "$Revision: 12818 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2010-10-08 08:29:14 +0200 (Fri, 08 Oct 2010)" );
	script_cve_id( "CVE-2010-3303", "CVE-2010-3763" );
	script_bugtraq_id( 43604 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "MantisBT Multiple Cross-site scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.mantisbt.org/bugs/view.php?id=12231" );
	script_xref( name: "URL", value: "http://www.mantisbt.org/bugs/view.php?id=12232" );
	script_xref( name: "URL", value: "http://www.mantisbt.org/bugs/view.php?id=12234" );
	script_xref( name: "URL", value: "http://www.mantisbt.org/bugs/view.php?id=12238" );
	script_xref( name: "URL", value: "http://www.mantisbt.org/bugs/view.php?id=12309" );
	script_xref( name: "URL", value: "http://www.mantisbt.org/bugs/changelog_page.php?version_id=111" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_dependencies( "mantis_detect.sc" );
	script_mandatory_keys( "mantisbt/detected" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "insight", value: "Multiple flaws exist in the application which allow remote authenticated
  attackers to inject arbitrary web script or HTML via:

  (1) A plugin name, related to 'manage_plugin_uninstall.php'

  (2) An 'enumeration' value

  (3) A 'String' value of a custom field, related to 'core/cfdefs/cfdef_standard.php'

  (4) project

  (5) category name to 'print_all_bug_page_word.php' or

  (6) 'Summary field', related to 'core/summary_api.php'" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to MantisBT version 1.2.3 or later" );
	script_tag( name: "summary", value: "This host is running MantisBT and is prone to multiple cross-site
  scripting vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to conduct cross-site scripting
  attacks." );
	script_tag( name: "affected", value: "MantisBT version prior to 1.2.3" );
	script_xref( name: "URL", value: "http://www.mantisbt.org/download.php" );
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
if(version_is_less( version: version, test_version: "1.2.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

