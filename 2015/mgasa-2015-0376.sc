if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.130015" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-10-15 10:41:33 +0300 (Thu, 15 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2015-0376" );
	script_tag( name: "insight", value: "Updated icedtea-web packages fix security vulnerabilities: It was discovered that IcedTea-Web did not properly sanitize applet URLs when storing applet trust settings. A malicious web page could use this flaw to inject trust-settings configuration, and cause applets to be executed without user approval (CVE-2015-5234). It was discovered that IcedTea-Web did not properly determine an applet's origin when asking the user if the applet should be run. A malicious page could use this flaw to cause IcedTea-Web to execute the applet without user approval, or confuse the user into approving applet execution based on an incorrectly indicated applet origin (CVE-2015-5235)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2015-0376.html" );
	script_cve_id( "CVE-2015-5234", "CVE-2015-5235" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2015-0376" );
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
	if(( res = isrpmvuln( pkg: "icedtea-web", rpm: "icedtea-web~1.5.3~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

