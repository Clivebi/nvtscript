if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.130005" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-10-15 06:54:58 +0300 (Thu, 15 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2015-0388" );
	script_tag( name: "insight", value: "Updated gdk-pixbuf packages fix security vulnerabilities: Security researcher Gustavo Grieco reported a heap overflow in gdk-pixbuf before 2.32.0. This issue is triggered by the scaling of a malformed tga format image and results in a potentially exploitable crash (CVE-2015-7673). Security researcher Gustavo Grieco reported a heap overflow in gdk-pixbuf before 2.32.1. This issue is triggered by the scaling of a malformed gif format image (CVE-2015-7674)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2015-0388.html" );
	script_cve_id( "CVE-2015-7673", "CVE-2015-7674" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2015-0388" );
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
	if(( res = isrpmvuln( pkg: "gdk-pixbuf2.0", rpm: "gdk-pixbuf2.0~2.32.1~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

