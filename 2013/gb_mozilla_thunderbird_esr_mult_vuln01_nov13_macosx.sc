CPE = "cpe:/a:mozilla:thunderbird_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804140" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-5604", "CVE-2013-5602", "CVE-2013-5601", "CVE-2013-5600", "CVE-2013-5599", "CVE-2013-5597", "CVE-2013-5590", "CVE-2013-5595" );
	script_bugtraq_id( 63430, 63424, 63428, 63427, 63423, 63422, 63415, 63421 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-11-07 19:28:51 +0530 (Thu, 07 Nov 2013)" );
	script_name( "Mozilla Thunderbird ESR Multiple Vulnerabilities-01 Nov13 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Thunderbird ESR and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Thunderbird ESR version 17.0.10 or later." );
	script_tag( name: "insight", value: "Multiple flaws due to:

  - Improper data initialization in the 'txXPathNodeUtils::getBaseURI' function.

  - An error in 'Worker::SetEventListener' function in the Web workers
implementation.

  - Use-after-free vulnerability in the
'nsEventListenerManager::SetEventHandler' function.

  - Use-after-free vulnerability in 'nsIOService::NewChannelFromURIWithProxyFlags'
function.

  - Use-after-free vulnerability in the 'nsIPresShell::GetPresContext' function.

  - Use-after-free vulnerability in 'nsDocLoader::doStopDocumentLoad' function.

  - Multiple unspecified vulnerabilities in the browser engine.

  - Improper memory allocation for unspecified functions by JavaScript engine." );
	script_tag( name: "affected", value: "Mozilla Thunderbird ESR version 17.x before 17.0.10 on Mac OS X" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code,
cause a denial of service and conduct buffer overflow attacks." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/55520" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2013/mfsa2013-96.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Thunderbird-ESR/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(vers && IsMatchRegexp( vers, "^17\\.0" )){
	if(version_is_less( version: vers, test_version: "17.0.10" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}

