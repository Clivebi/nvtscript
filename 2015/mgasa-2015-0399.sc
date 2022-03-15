if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131094" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-10-15 06:54:51 +0300 (Thu, 15 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2015-0399" );
	script_tag( name: "insight", value: "Adobe Flash Player 11.2.202.535 contains fixes to critical security vulnerabilities found in earlier versions that could potentially allow an attacker to take control of the affected system. This update resolves a vulnerability that could be exploited to bypass the same-origin-policy and lead to information disclosure (CVE-2015-7628). This update includes a defense-in-depth feature in the Flash broker API (CVE-2015-5569). This update resolves use-after-free vulnerabilities that could lead to code execution (CVE-2015-7629, CVE-2015-7631, CVE-2015-7643, CVE-2015-7644). This update resolves a buffer overflow vulnerability that could lead to code execution (CVE-2015-7632). This update resolves memory corruption vulnerabilities that could lead to code execution (CVE-2015-7625, CVE-2015-7626, CVE-2015-7627, CVE-2015-7630, CVE-2015-7633, CVE-2015-7634)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2015-0399.html" );
	script_cve_id( "CVE-2015-7625", "CVE-2015-7626", "CVE-2015-7627", "CVE-2015-7628", "CVE-2015-7629", "CVE-2015-7630", "CVE-2015-7631", "CVE-2015-7632", "CVE-2015-7633", "CVE-2015-7634", "CVE-2015-7643", "CVE-2015-7644" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2015-0399" );
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
	if(( res = isrpmvuln( pkg: "flash-player-plugin", rpm: "flash-player-plugin~11.2.202.535~1.mga5.nonfree", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

