CPE = "cpe:/a:ibm:soliddb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803761" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2013-3031" );
	script_bugtraq_id( 59637 );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-20 12:22:19 +0530 (Fri, 20 Sep 2013)" );
	script_name( "IBM solidDB Stored Procedure Call Handling Denial of Service Vulnerability" );
	script_tag( name: "summary", value: "This host is running IBM solidDB and is prone to denial of service
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade IBM solidDB to 6.0.1070, 6.3.0.56, 6.5.0.12, 7.0.0.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "insight", value: "The flaw is due to an error when calling stored procedures without input
  parameters when the parameters have default values. This can be exploited
  to trigger an exception and cause the server to shutdown." );
	script_tag( name: "affected", value: "IBM solidDB 6.0.x before 6.0.1070, 6.3.x before 6.3.0.56,
  6.5.x before 6.5.0.12, and 7.0.x before 7.0.0.4." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause a denial of service." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/53299" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/84593" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21643599" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg1IC94044" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg1IC94043" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg1IC88797" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg1IC88796" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "gb_ibm_soliddb_detect.sc" );
	script_mandatory_keys( "IBM-soliddb/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ibmPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ibmVer = get_app_version( cpe: CPE, port: ibmPort )){
	exit( 0 );
}
if(IsMatchRegexp( ibmVer, "^6\\.0\\.*" )){
	if(version_is_less( version: ibmVer, test_version: "6.0.1070" )){
		report = report_fixed_ver( installed_version: ibmVer, fixed_version: "6.0.1070" );
		security_message( port: ibmPort, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( ibmVer, "^06\\.3.*" )){
	if(version_is_less( version: ibmVer, test_version: "06.30.0056" )){
		report = report_fixed_ver( installed_version: ibmVer, fixed_version: "06.30.0056" );
		security_message( port: ibmPort, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( ibmVer, "^6\\.5\\.*" )){
	if(version_is_less( version: ibmVer, test_version: "6.5.0.12" )){
		report = report_fixed_ver( installed_version: ibmVer, fixed_version: "6.5.0.12" );
		security_message( port: ibmPort, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( ibmVer, "^7\\.0\\.*" )){
	if(version_is_less( version: ibmVer, test_version: "7.0.0.4" )){
		report = report_fixed_ver( installed_version: ibmVer, fixed_version: "7.0.0.4" );
		security_message( port: ibmPort, data: report );
	}
}

