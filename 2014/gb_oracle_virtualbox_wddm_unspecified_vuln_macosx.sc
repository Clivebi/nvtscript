CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804434" );
	script_version( "2019-07-05T09:12:25+0000" );
	script_cve_id( "CVE-2014-2441" );
	script_bugtraq_id( 66868 );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-07-05 09:12:25 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2014-04-18 12:52:15 +0530 (Fri, 18 Apr 2014)" );
	script_name( "Oracle VM VirtualBox Graphics Driver(WDDM) Unspecified Vulnerability (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Oracle VM VirtualBox and is prone to unspecified
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is  due to an error within the Graphics driver(WDDM) for Windows
guests component and can be exploited by disclose, update, insert, or delete
certain data and to cause a crash." );
	script_tag( name: "impact", value: "Successful exploitation will allow local users to disclose sensitive
information, manipulate certain data, and cause a DoS (Denial of
Service)." );
	script_tag( name: "affected", value: "Oracle Virtualization VirtualBox 4.1.x before 4.1.32, 4.2.x before 4.2.24,
and 4.3.x before 4.3.10 on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Oracle VM VirtualBox version 4.1.32, 4.2.24, 4.3.10 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57937" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_oracle_virtualbox_detect_macosx.sc" );
	script_mandatory_keys( "Oracle/VirtualBox/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!virtualVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( virtualVer, "^(4\\.(1|2|3))" )){
	if(version_in_range( version: virtualVer, test_version: "4.2.0", test_version2: "4.2.23" ) || version_in_range( version: virtualVer, test_version: "4.3.0", test_version2: "4.3.9" ) || version_in_range( version: virtualVer, test_version: "4.1.0", test_version2: "4.1.31" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

