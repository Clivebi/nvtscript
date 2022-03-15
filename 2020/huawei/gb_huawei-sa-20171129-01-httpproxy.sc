if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143972" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-26 03:19:08 +0000 (Tue, 26 May 2020)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)" );
	script_cve_id( "CVE-2016-5386" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: A CGI application vulnerability in Some Huawei Products (huawei-sa-20171129-01-httpproxy)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "Some open source software used by Huawei does not attempt to address RFC 3875 section 4.1.18 namespace conflicts." );
	script_tag( name: "insight", value: "Some open source software used by Huawei does not attempt to address RFC 3875 section 4.1.18 namespace conflicts and therefore does not protect applications from the presence of untrusted client data in the HTTP_PROXY environment variable, which might allow remote attackers to redirect an application's outbound HTTP traffic to an arbitrary proxy server via a crafted Proxy header in an HTTP request. (Vulnerability ID: HWPSIRT-2016-07052)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-5386.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references." );
	script_tag( name: "impact", value: "Remote attackers can redirect an application's outbound HTTP traffic to an arbitrary proxy server via a crafted Proxy header in an HTTP request by exploit this vulnerability." );
	script_tag( name: "affected", value: "AR3200 versions V200R005C30 V200R005C32 V200R006C10 V200R006C11 V200R006C12 V200R006C13 V200R006C15 V200R006C16 V200R006C17 V200R007C00" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171129-01-httpproxy-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:ar3200_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = toupper( infos["version"] );
patch = get_kb_item( "huawei/vrp/patch" );
if(cpe == "cpe:/o:huawei:ar3200_firmware"){
	if(IsMatchRegexp( version, "^V200R005C30" ) || IsMatchRegexp( version, "^V200R005C32" ) || IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R006C11" ) || IsMatchRegexp( version, "^V200R006C12" ) || IsMatchRegexp( version, "^V200R006C13" ) || IsMatchRegexp( version, "^V200R006C15" ) || IsMatchRegexp( version, "^V200R006C16" ) || IsMatchRegexp( version, "^V200R006C17" ) || IsMatchRegexp( version, "^V200R007C00" )){
		if(!patch || version_is_less( version: patch, test_version: "V200R008C50" )){
			report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R008C50" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

