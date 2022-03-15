if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131121" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-11-08 13:02:15 +0200 (Sun, 08 Nov 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2015-0420" );
	script_tag( name: "insight", value: "Josh Kupershmidt discovered the pgCrypto extension could expose several bytes of server memory if the crypt() function was provided a too-short salt. An attacker could use this flaw to read private data. (CVE-2015-5288) Oskari Saarenmaa discovered that the json and jsonb handlers could exhaust available stack space. An attacker could use this flaw to perform a denial of service attack. (CVE-2015-5289) The postgresql9.3 and postgresql9.4 packages have been updated to versions 9.3.10 and 9.4.5, respectively, to fix these issues. See the upstream release notes for more details." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2015-0420.html" );
	script_cve_id( "CVE-2015-5288", "CVE-2015-5289" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2015-0420" );
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
	if(( res = isrpmvuln( pkg: "3", rpm: "3~9.3.10~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "4", rpm: "4~9.4.5~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

