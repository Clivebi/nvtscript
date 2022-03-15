CPE = "cpe:/a:oracle:netbeans";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809473" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_cve_id( "CVE-2016-5537" );
	script_bugtraq_id( 93686 );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-11-16 11:36:06 +0530 (Wed, 16 Nov 2016)" );
	script_name( "Oracle NetBeans IDE Import Directory Traversal Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Oracle NetBeans
  IDE and is prone to directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an improper validation
  of '../' characters in an archive entry of a ZIP file imported as a project." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  users with certain permissions to perform unauthorized update, insert or
  delete access to some of NetBeans accessible data as well as unauthorized read
  access to a subset of NetBeans accessible data and unauthorized ability to cause
  a partial denial of service (partial DOS) of NetBeans." );
	script_tag( name: "affected", value: "Oracle NetBeans IDE version 8.1 on Windows" );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40588" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_oracle_netbeans_ide_detect_win.sc" );
	script_mandatory_keys( "Oracle/NetBeans/IDE/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!netVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_equal( version: netVer, test_version: "8.1" )){
	report = report_fixed_ver( installed_version: netVer, fixed_version: "Apply the patch" );
	security_message( data: report );
	exit( 0 );
}

