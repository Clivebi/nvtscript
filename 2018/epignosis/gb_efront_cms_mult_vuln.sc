if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113104" );
	script_version( "2021-05-28T07:06:21+0000" );
	script_tag( name: "last_modification", value: "2021-05-28 07:06:21 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2018-02-06 15:00:00 +0100 (Tue, 06 Feb 2018)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-26 21:01:00 +0000 (Mon, 26 Feb 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2015-4461", "CVE-2015-4462", "CVE-2015-4463" );
	script_name( "eFront CMS 3.6.15.4 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_efront_detect.sc" );
	script_mandatory_keys( "efront/detected" );
	script_tag( name: "summary", value: "eFront CMS is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Vulnerabilities:

Absolute path traversal: Allows remote Professor users to obtain sensitive information via a full pathname in the other parameter.

Unrestricted file upload vulnerability: Allows remote authenticated users to execute arbitrary code by uploading a file from a local URL, then accessing it via a direct request to the file in www/content/lessons/\"lesson number\"/\"directory name\".

Unrestricted file upload vulnerability: Allows remote authenticated users to execute arbitrary code by uploading a file with an executable extension prepended to a crafted parameter, then accessing it via a direct request to the file in www/content/lessons/\"lesson number\"/\"directory name\"" );
	script_tag( name: "affected", value: "eFront CMS through version 3.6.15.4" );
	script_tag( name: "solution", value: "Update to eFront CMS version 3.6.15.5 or above" );
	script_xref( name: "URL", value: "http://mohankallepalli.blogspot.de/2015/05/eFront-cms-multiple-bugs.html" );
	exit( 0 );
}
CPE = "cpe:/a:efrontlearning:efront";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( port: port, cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "3.6.15.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.6.15.5" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

