if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131226" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2016-02-18 07:27:34 +0200 (Thu, 18 Feb 2016)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2016-0077" );
	script_tag( name: "insight", value: "Multiple vulnerabilities in the graphite2 font library can result in information disclosure, denial-of-service (application crashes), or code execution via out-of-bounds reads, a NULL pointer dereference, and a heap-based buffer overflow (CVE-2016-1521, CVE-2016-1522, CVE-2016-1523, CVE-2016-1526). Firefox includes a bundled copy of the graphite2 library, which has been updated in Firefox ESR 38.6.1." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2016-0077.html" );
	script_cve_id( "CVE-2016-1521", "CVE-2016-1522", "CVE-2016-1523", "CVE-2016-1526" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2016-0077" );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
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
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~38.6.1~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "firefox-l10n", rpm: "firefox-l10n~38.6.1~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "graphite2", rpm: "graphite2~1.3.5~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

