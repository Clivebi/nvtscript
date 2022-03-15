CPE = "cpe:/a:apache:ambari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809085" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2015-3270" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-11-04 16:26:03 +0530 (Fri, 04 Nov 2016)" );
	script_name( "Apache Ambari Privilege Escalation Vulnerability" );
	script_tag( name: "summary", value: "This host is running Apache Ambari
  and is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an access to the user
  resource endpoint is not protected such that an authenticated user can
  remotely escalate his/her permissions to administrative level." );
	script_tag( name: "impact", value: "Successfully exploitation will allow remote
  authenticated users to gain administrative privileges, possibly related to
  changing passwords." );
	script_tag( name: "affected", value: "Apache Ambari versions 1.7.0, 2.0.0, 2.0.1,
  2.1.0" );
	script_tag( name: "solution", value: "Upgrade to Apache Ambari version 2.0.2 or
  2.1.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2015/10/13/3" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/AMBARI/Ambari+Vulnerabilities" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_ambari_detect.sc" );
	script_mandatory_keys( "Apache/Ambari/Installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!amb_Port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!amb_Ver = get_app_version( cpe: CPE, port: amb_Port )){
	exit( 0 );
}
if( version_in_range( version: amb_Ver, test_version: "1.7.0", test_version2: "2.0.1" ) ){
	fix = "2.0.2";
	VULN = TRUE;
}
else {
	if(version_is_equal( version: amb_Ver, test_version: "2.1.0" )){
		fix = "2.1.1";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: amb_Ver, fixed_version: fix );
	security_message( data: report, port: amb_Port );
	exit( 0 );
}

