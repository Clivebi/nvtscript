if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107095" );
	script_version( "$Revision: 12363 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-24 13:17:56 +0100 (Thu, 24 Nov 2016)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2016-4306" );
	script_name( "Kaspersky Internet Security KLDISK Driver Multiple Kernel Memory Disclosure Vulnerabilities (Windows)" );
	script_xref( name: "URL", value: "http://www.talosintelligence.com/reports/TALOS-2016-0168/" );
	script_xref( name: "URL", value: "https://support.kaspersky.com/vulnerability.aspx?el=12430#250816_2" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_kaspersky_av_detect.sc" );
	script_mandatory_keys( "Kaspersky/TotNetSec/Ver" );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to leak sensitive information such as privileged tokens or kernel memory addresses that may
  be useful in bypassing kernel mitigations. An unprivileged user can run a program from user mode to trigger this vulnerability." );
	script_tag( name: "affected", value: "Kaspersky Internet Security 16.0.0.614" );
	script_tag( name: "insight", value: "This flaws occurs due to the specially crafted IOCTL requests that can cause the driver to return out of bounds kernel memory." );
	script_tag( name: "solution", value: "Apply the patch from the advisory." );
	script_tag( name: "summary", value: "This host is running Kaspersky Internet Security 16.0.0.614 and is prone
  to multiple kernel memory disclosure vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:kaspersky:kaspersky_total_security";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!kisVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_equal( version: kisVer, test_version: "16.0.0.614" )){
	report = report_fixed_ver( installed_version: kisVer, fixed_version: "See references" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

