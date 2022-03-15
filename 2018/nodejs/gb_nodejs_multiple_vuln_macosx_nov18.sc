CPE = "cpe:/a:nodejs:node.js";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814517" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-12121", "CVE-2018-12122", "CVE-2018-12123" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-20 21:15:00 +0000 (Fri, 20 Mar 2020)" );
	script_tag( name: "creation_date", value: "2018-11-29 13:13:28 +0530 (Thu, 29 Nov 2018)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Node.js Multiple Vulnerabilities-Nov18 (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with Node.js and is
  prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error in Hostname spoofing in URL parser for javascript protocol, If a
    Node.js is using url.parse() to determine the URL hostname, that hostname
    can be spoofed by using a mixed case 'javascript:',

  - An error in Slowloris HTTP, An attacker can cause a Denial of Service
    (DoS) by sending headers very slowly keeping HTTP or HTTPS connections
    and associated resources alive for a long period of time and

  - Denial of Service with large HTTP headers, By using a combination of many
    requests with maximum sized headers (almost 80 KB per connection), and
    carefully timed completion of the headers, it is possible to cause the
    HTTP server to abort from heap allocation failure." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct denial of service and spoofing attacks." );
	script_tag( name: "affected", value: "Node.js All versions prior to 6.15.0,
  8.14.0, 10.14.0 and 11.3.0 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Node.js version 6.15.0, 8.14.0,
  or 10.14.0, 11.3.0 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://nodejs.org/en/blog/vulnerability/november-2018-security-releases" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_nodejs_detect_macosx.sc" );
	script_mandatory_keys( "Nodejs/MacOSX/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
nodejsVer = infos["version"];
appPath = infos["location"];
if( version_in_range( version: nodejsVer, test_version: "6.0", test_version2: "6.14.0" ) ){
	fix = "6.15.0";
}
else {
	if( version_in_range( version: nodejsVer, test_version: "8.0", test_version2: "8.13.0," ) ){
		fix = "8.14.0";
	}
	else {
		if( version_in_range( version: nodejsVer, test_version: "10.0", test_version2: "10.13.0" ) ){
			fix = "10.14.0";
		}
		else {
			if(version_in_range( version: nodejsVer, test_version: "11.0", test_version2: "11.2.0" )){
				fix = "11.3.0";
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: nodejsVer, fixed_version: fix, install_path: appPath );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

