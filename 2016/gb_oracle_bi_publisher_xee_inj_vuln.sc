CPE = "cpe:/a:oracle:business_intelligence_publisher";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809733" );
	script_version( "2020-10-26T14:42:42+0000" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-26 14:42:42 +0000 (Mon, 26 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-11-25 17:10:49 +0530 (Fri, 25 Nov 2016)" );
	script_cve_id( "CVE-2016-3473" );
	script_bugtraq_id( 93719 );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Oracle BI Publisher XML External Entity Injection Vulnerability (cpuoct2016)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_oracle_bi_publisher_detect.sc" );
	script_mandatory_keys( "oracle/bi_publisher/detected" );
	script_tag( name: "summary", value: "Oracle BI Publisher is prone to a XML external entity injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in the 'Security' sub-component
  of Oracle BI Publisher." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow remote attackers to conduct
  a XML External Entity (XXE) injection attack on the affected system." );
	script_tag( name: "affected", value: "Oracle BI Publisher versions 11.1.1.7.0, 11.1.1.9.0, 12.2.1.0.0." );
	script_tag( name: "solution", value: "See the referenced advisory for a solution." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40590" );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpuoct2016.html#AppendixFMW" );
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
version = infos["version"];
location = infos["location"];
if(version_is_equal( version: version, test_version: "11.1.1.7.0" ) || version_is_equal( version: version, test_version: "11.1.1.9.0" ) || version_is_equal( version: version, test_version: "12.2.1.0.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

