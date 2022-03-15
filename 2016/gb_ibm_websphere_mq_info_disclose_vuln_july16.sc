CPE = "cpe:/a:ibm:websphere_mq";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808619" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_cve_id( "CVE-2015-7462" );
	script_bugtraq_id( 91073 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-07-15 18:17:58 +0530 (Fri, 15 Jul 2016)" );
	script_name( "IBM WebSphere MQ Information Disclosure Vulnerability - July16" );
	script_tag( name: "summary", value: "This host is installed with IBM WebSphere MQ
  and is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the mqcertck tool
  which was newly added in MQ could trace certificate keystore passwords." );
	script_tag( name: "impact", value: "Successful exploitation will allow local users
  to discover cleartext certificate-keystore passwords within MQ trace output by
  leveraging administrator privileges to execute the mqcertck program." );
	script_tag( name: "affected", value: "IBM WebSphere MQ version 8.0.0.4" );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere MQ version 8.0.0.5
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21984557" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_ibm_websphere_mq_consolidation.sc" );
	script_mandatory_keys( "ibm_websphere_mq/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_is_equal( version: version, test_version: "8.0.0.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0.0.5", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

