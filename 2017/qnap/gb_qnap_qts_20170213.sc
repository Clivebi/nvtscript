if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140172" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_version( "$Revision: 11983 $" );
	script_name( "QNAP QTS Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.qnap.com/de-de/releasenotes/" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/141123/QNAP-QTS-4.2.x-XSS-Command-Injection-Transport-Issues.html" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-02-22 13:24:30 +0100 (Wed, 22 Feb 2017)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_require_ports( "Services/www", 80, 8080 );
	script_mandatory_keys( "qnap/qts", "qnap/version", "qnap/build" );
	script_tag( name: "vuldetect", value: "Check the firmware version" );
	script_tag( name: "solution", value: "Update to QNAP QTS 4.2.3 build 20170213 or newer." );
	script_tag( name: "summary", value: "QNAP QTS software firmware update functionality include Missing Transport
Layer Security (CWE-319), Command Injection (CWE-77) and Cross-Site
Scripting (CWE-79) vulnerabilities. An attacker in a privileged network
position can Man-in-The-Middle the firmware update check and exploit the
command injection vulnerability to execute arbitrary commands on the
targeted device.

QNAP QTS myQNAPcloud functionality includes Improper Certificate Validation
(CWE-295) vulnerability. The attacker in a privileged network position can
exploit this vulnerability to eavesdrop the myQNAPcloud credentials.

QNAP QTS media scraping functionality automatically scrapes Google and IMDB
for media information (for example album cover images). The functionality
contains an Information Exposure (CWE-200) vulnerability. The attacker in a
privileged network position can eavesdrop the requests performed." );
	script_tag( name: "affected", value: "QNAP QTS < 4.2.3 build 20170213, all models" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!version = get_kb_item( "qnap/version" )){
	exit( 0 );
}
if(!build = get_kb_item( "qnap/build" )){
	exit( 0 );
}
cv = version + "." + build;
if(version_is_less( version: cv, test_version: "4.2.3.20170213" )){
	report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.2.3", fixed_build: "20170213" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

