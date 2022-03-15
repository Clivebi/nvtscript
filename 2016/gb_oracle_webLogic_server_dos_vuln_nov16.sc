CPE = "cpe:/a:bea:weblogic_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809713" );
	script_version( "2021-05-10T09:07:58+0000" );
	script_cve_id( "CVE-2016-5488" );
	script_bugtraq_id( 93627 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-05-10 09:07:58 +0000 (Mon, 10 May 2021)" );
	script_tag( name: "creation_date", value: "2016-11-02 17:11:57 +0530 (Wed, 02 Nov 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Oracle WebLogic Server Denial of Service Vulnerability - Nov16" );
	script_tag( name: "summary", value: "Oracle WebLogic Server is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to some unspecified error in the Web Container component
  within the Oracle WebLogic Server." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause a partial
  denial of service condition." );
	script_tag( name: "affected", value: "Oracle WebLogic Server versions 10.3.6.0 and 12.1.3.0." );
	script_tag( name: "solution", value: "Apply the update from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_oracle_weblogic_consolidation.sc" );
	script_mandatory_keys( "oracle/weblogic/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "10.3.6.0.0" ) || version_is_equal( version: version, test_version: "12.1.3.0.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

