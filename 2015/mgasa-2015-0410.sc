if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131102" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-10-26 09:36:00 +0200 (Mon, 26 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2015-0410" );
	script_tag( name: "insight", value: "Updated chromium-browser-stable packages fix security vulnerabilities: Several flaws were found in the processing of malformed web content. A web page containing malicious content could cause Chromium to crash, execute arbitrary code, or disclose sensitive information when visited by the victim (CVE-2015-6755, CVE-2015-6756, CVE-2015-6757, CVE-2015-6758, CVE-2015-6759, CVE-2015-6760, CVE-2015-6761, CVE-2015-6762, CVE-2015-6763)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2015-0410.html" );
	script_cve_id( "CVE-2015-6755", "CVE-2015-6756", "CVE-2015-6757", "CVE-2015-6758", "CVE-2015-6759", "CVE-2015-6760", "CVE-2015-6761", "CVE-2015-6762", "CVE-2015-6763" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2015-0410" );
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
	if(( res = isrpmvuln( pkg: "chromium-browser-stable", rpm: "chromium-browser-stable~46.0.2490.80~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

