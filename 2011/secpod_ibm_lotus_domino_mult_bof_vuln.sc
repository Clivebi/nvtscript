CPE = "cpe:/a:ibm:lotus_domino";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902418" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-0913", "CVE-2011-0914", "CVE-2011-0915" );
	script_name( "IBM Lotus Domino Multiple Remote Buffer Overflow Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43208" );
	script_xref( name: "URL", value: "http://zerodayinitiative.com/advisories/ZDI-11-052/" );
	script_xref( name: "URL", value: "http://zerodayinitiative.com/advisories/ZDI-11-053/" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21461514" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_hcl_domino_consolidation.sc" );
	script_mandatory_keys( "hcl/domino/detected" );
	script_tag( name: "impact", value: "Successful exploitation may allow remote attackers to execute arbitrary code
  in the context of the Lotus Domino server process." );
	script_tag( name: "affected", value: "IBM Lotus Domino versions prior to 8.5.3" );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Error in 'ndiiop.exe' in the DIIOP implementation, which allows remote
    attackers to execute arbitrary code via a GIOP getEnvironmentString
    request.

  - Integer signedness error in 'ndiiop.exe' in the DIIOP implementation, which
    allows remote attackers to execute arbitrary code via a GIOP client
    request.

  - Error in 'nrouter.exe', which allows remote attackers to execute arbitrary
    code via a long name parameter in a Content-Type header in a malformed
    Notes calendar meeting request." );
	script_tag( name: "solution", value: "Upgrade to IBM Lotus Domino version 8.5.3 or later" );
	script_tag( name: "summary", value: "IBM Lotus Domino Server is prone to remote buffer overflow vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "8.5.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.5.3" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

