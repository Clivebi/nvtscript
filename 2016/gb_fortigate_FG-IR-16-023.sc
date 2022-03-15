CPE = "cpe:/h:fortinet:fortigate";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105875" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-07-12T08:06:48+0000" );
	script_cve_id( "CVE-2016-6909" );
	script_name( "Fortinet FortiGate Cookie Parser Buffer Overflow Vulnerability (FG-IR-16-023) - Version Check" );
	script_xref( name: "URL", value: "https://www.fortiguard.com/psirt/FG-IR-16-023" );
	script_tag( name: "impact", value: "This vulnerability, when exploited by a crafted HTTP request, can result in execution control being taken over." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to release 5.x.
Upgrade to release 4.3.9 or above for models not compatible with FortiOS 5.x." );
	script_tag( name: "summary", value: "FortiGate firmware (FOS) released before Aug 2012 has a cookie parser buffer overflow vulnerability." );
	script_tag( name: "affected", value: "FortiGate (FOS):

4.3.8 and below

4.2.12 and below

4.1.10 and below" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-07-12 08:06:48 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2016-08-18 11:05:04 +0200 (Thu, 18 Aug 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "FortiOS Local Security Checks" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_fortigate_version.sc" );
	script_mandatory_keys( "fortigate/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^4\\.1\\." )){
	fix = "4.1.11";
}
if(IsMatchRegexp( version, "^4\\.2\\." )){
	fix = "4.2.13";
}
if(IsMatchRegexp( version, "^4\\.3\\." )){
	fix = "4.3.9";
}
if(!fix){
	exit( 99 );
}
if(version_is_less( version: version, test_version: fix )){
	report = report_fixed_ver( installed_version: version, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

