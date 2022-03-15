if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131123" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-11-08 13:02:17 +0200 (Sun, 08 Nov 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2015-0418" );
	script_tag( name: "insight", value: "Yves Younan discovered that NTP incorrectly handled logfile and keyfile directives. In a non-default configuration, a remote authenticated attacker could possibly use this issue to cause NTP to enter a loop, resulting in a denial of service (CVE-2015-7850). Yves Younan discovered that NTP incorrectly handled reference clock memory. A malicious refclock could possibly use this issue to cause NTP to crash, resulting in a denial of service, or possibly execute arbitrary code (CVE-2015-7853). John D Doug Birdwell discovered that NTP incorrectly handled decoding certain bogus values. An attacker could possibly use this issue to cause NTP to crash, resulting in a denial of service (CVE-2015-7855)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2015-0418.html" );
	script_cve_id( "CVE-2015-7850", "CVE-2015-7853", "CVE-2015-7855" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2015-0418" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Mageia Linux Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "MAGEIA5"){
	if(( res = isrpmvuln( pkg: "ntp", rpm: "ntp~4.2.6p5~24.3.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

