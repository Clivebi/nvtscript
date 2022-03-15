if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131185" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2016-01-15 08:29:01 +0200 (Fri, 15 Jan 2016)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2016-0018" );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2016-0018.html" );
	script_cve_id( "CVE-2015-6761", "CVE-2015-6818", "CVE-2015-6820", "CVE-2015-6821", "CVE-2015-6822", "CVE-2015-6823", "CVE-2015-6824", "CVE-2015-6825", "CVE-2015-6826", "CVE-2015-8216", "CVE-2015-8219", "CVE-2015-8363", "CVE-2015-8364", "CVE-2015-8365", "CVE-2015-8661", "CVE-2015-8662", "CVE-2015-8663" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2016-0018" );
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
	if(( res = isrpmvuln( pkg: "ffmpeg", rpm: "ffmpeg~2.4.12~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

