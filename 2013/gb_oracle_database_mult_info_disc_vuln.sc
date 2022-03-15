CPE = "cpe:/a:oracle:database_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803956" );
	script_version( "$Revision: 12634 $" );
	script_cve_id( "CVE-2013-3826", "CVE-2013-5771" );
	script_bugtraq_id( 63046, 63044 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-04 08:26:26 +0100 (Tue, 04 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2013-10-28 14:27:36 +0530 (Mon, 28 Oct 2013)" );
	script_name( "Oracle Database Server Multiple Information Disclosure Vulnerabilities" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to obtain potentially sensitive
  information and manipulate certain data." );
	script_tag( name: "affected", value: "Oracle Database Server version 11.1.0.7, 11.2.0.2, 11.2.0.3, and 12.1.0.1
  are affected." );
	script_tag( name: "insight", value: "Multiple flaws exist in Core RDBMS component and XML Parser component, no
  further information available at this moment." );
	script_tag( name: "solution", value: "Apply the updates from the referenced advisories." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "summary", value: "This host is installed with Oracle Database Server and is prone to multiple
  information disclosure vulnerabilities." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/55322" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuoct2013verbose-1899842.html#DB" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html#AppendixDB" );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_dependencies( "oracle_tnslsnr_version.sc" );
	script_mandatory_keys( "OracleDatabaseServer/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ver = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( ver, "^(11\\.[1|2]\\.0|12\\.1\\.0)" )){
	if(version_in_range( version: ver, test_version: "11.2.0.2", test_version2: "11.2.0.3" ) || version_is_equal( version: ver, test_version: "12.1.0.1" ) || version_is_equal( version: ver, test_version: "11.1.0.7" )){
		security_message( port );
	}
}

