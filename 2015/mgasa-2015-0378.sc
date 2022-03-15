if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.130013" );
	script_version( "2020-11-12T08:54:04+0000" );
	script_tag( name: "creation_date", value: "2015-10-15 10:41:31 +0300 (Thu, 15 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-11-12 08:54:04 +0000 (Thu, 12 Nov 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2015-0378" );
	script_tag( name: "insight", value: "Updated owncloud package fixes security vulnerabilities: In ownCloud before 8.0.6, due to an incorrect usage of an ownCloud internal file system function the passed path to the file scanner was resolved relatively. An authenticated adversary may thus be able to get a listing of directories (but not the containing files) existing on the filesystem. However, it is not possible to access any of these files (CVE-2015-6500). In ownCloud before 8.0.6, due to not properly checking the ownership of a calendar, an authenticated attacker is able to download calendars of other users via the calid GET parameter to export.php in /apps/calendar/ (CVE-2015-6670). The owncloud package has been updated to version 8.0.8, which fixes these issues, as well as other bugs and other not-yet-disclosed security issues." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2015-0378.html" );
	script_cve_id( "CVE-2015-6500", "CVE-2015-6670" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2015-0378" );
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
	if(( res = isrpmvuln( pkg: "owncloud", rpm: "owncloud~8.0.8~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

