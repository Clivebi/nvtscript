if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892656" );
	script_version( "2021-08-24T12:01:48+0000" );
	script_cve_id( "CVE-2021-3504" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 12:01:48 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-21 18:35:00 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-05-12 03:00:14 +0000 (Wed, 12 May 2021)" );
	script_name( "Debian LTS: Security Advisory for hivex (DLA-2656-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/05/msg00011.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2656-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2656-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/988024" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'hivex'
  package(s) announced via the DLA-2656-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Jemery Galindo discovered an out-of-bounds memory access in Hivex,
a library to parse Windows Registry hive files." );
	script_tag( name: "affected", value: "'hivex' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.3.13-2+deb9u1.

We recommend that you upgrade your hivex packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libhivex-bin", ver: "1.3.13-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libhivex-dev", ver: "1.3.13-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libhivex-ocaml", ver: "1.3.13-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libhivex-ocaml-dev", ver: "1.3.13-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libhivex0", ver: "1.3.13-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libhivex0-dbg", ver: "1.3.13-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwin-hivex-perl", ver: "1.3.13-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-hivex", ver: "1.3.13-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-hivex", ver: "1.3.13-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-hivex", ver: "1.3.13-2+deb9u1", rls: "DEB9" ) )){
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
