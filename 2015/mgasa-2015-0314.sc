if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.130065" );
	script_version( "2020-03-03T07:50:03+0000" );
	script_tag( name: "creation_date", value: "2015-10-15 10:42:17 +0300 (Thu, 15 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-03-03 07:50:03 +0000 (Tue, 03 Mar 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2015-0314" );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2015-0314.html" );
	script_cve_id( "CVE-2015-4715", "CVE-2015-4717", "CVE-2015-4718" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2015-0314" );
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
	if(( res = isrpmvuln( pkg: "owncloud", rpm: "owncloud~8.0.5~1.2.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

