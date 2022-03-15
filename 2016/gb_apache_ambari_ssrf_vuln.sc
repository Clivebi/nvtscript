CPE = "cpe:/a:apache:ambari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809087" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2015-1775" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-11-04 16:26:03 +0530 (Fri, 04 Nov 2016)" );
	script_name( "Apache Ambari Server Side Request Forgery Vulnerability" );
	script_tag( name: "summary", value: "This host is running Apache Ambari
  and is prone to server-side request forgery vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a server-side request forgery
  vulnerability in the proxy endpoint (api/v1/proxy)." );
	script_tag( name: "impact", value: "Successfully exploitation will allow remote
  authenticated users to conduct port scans and access unsecured services." );
	script_tag( name: "affected", value: "Apache Ambari versions 1.5.0 to 2.0.2" );
	script_tag( name: "solution", value: "Upgrade to Apache Ambari version 2.1.0 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2015/10/13/2" );
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
if(version_in_range( version: amb_Ver, test_version: "1.5.0", test_version2: "2.0.2" )){
	report = report_fixed_ver( installed_version: amb_Ver, fixed_version: "2.1.0" );
	security_message( data: report, port: amb_Port );
	exit( 0 );
}

