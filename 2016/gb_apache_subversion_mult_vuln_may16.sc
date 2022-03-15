CPE = "cpe:/a:apache:subversion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807684" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2015-5343" );
	script_tag( name: "cvss_base", value: "8.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:C" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-05-02 15:57:20 +0530 (Mon, 02 May 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Apache Subversion Multiple Vulnerabilities May-16" );
	script_tag( name: "summary", value: "This host is installed with Apache Subversion
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to an integer
  overflow in 'util.c' script in mod_dav_svn when parsing skel-encoded request
  bodies." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to cause a denial of service and to possibly execute arbitrary code
  under the context of the httpd process." );
	script_tag( name: "affected", value: "Apache subversion version 1.7.0 to 1.8.14,
  and 1.9.0 through 1.9.2" );
	script_tag( name: "solution", value: "Upgrade to Apache subversion version 1.8.15,
  or 1.9.3, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://subversion.apache.org/security/CVE-2015-5343-advisory.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_subversion_remote_detect.sc" );
	script_mandatory_keys( "Subversion/installed" );
	script_require_ports( "Services/www", 3690 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!sub_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!subver = get_app_version( cpe: CPE, port: sub_port )){
	exit( 0 );
}
if( version_in_range( version: subver, test_version: "1.9.0", test_version2: "1.9.2" ) ){
	fix = "1.9.3";
	VULN = TRUE;
}
else {
	if(version_in_range( version: subver, test_version: "1.7.0", test_version2: "1.8.14" )){
		fix = "1.8.15";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: subver, fixed_version: fix );
	security_message( data: report, port: sub_port );
	exit( 0 );
}

