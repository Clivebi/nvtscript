if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878054" );
	script_version( "2021-07-19T02:00:45+0000" );
	script_cve_id( "CVE-2019-20454" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-19 02:00:45 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-09 03:15:00 +0000 (Thu, 09 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-07-12 03:19:21 +0000 (Sun, 12 Jul 2020)" );
	script_name( "Fedora: Security Advisory for mingw-pcre2 (FEDORA-2020-b11cf352bd)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-b11cf352bd" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OQRAHYHLRNMBTPR3KXVM27NSZP3KTOPI" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-pcre2'
  package(s) announced via the FEDORA-2020-b11cf352bd advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Cross compiled Perl-compatible regular expression library for use with mingw32.

PCRE has its own native API, but a set of 'wrapper' functions that are based on
the POSIX API are also supplied in the library libpcreposix. Note that this
just provides a POSIX calling interface to PCRE: the regular expressions
themselves still follow Perl syntax and semantics. The header file
for the POSIX-style functions is called pcreposix.h." );
	script_tag( name: "affected", value: "'mingw-pcre2' package(s) on Fedora 31." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "mingw-pcre2", rpm: "mingw-pcre2~10.33~3.fc31", rls: "FC31" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

