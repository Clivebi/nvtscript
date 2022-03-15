if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704557" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-18408" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-01 11:15:00 +0000 (Fri, 01 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-11-02 03:00:06 +0000 (Sat, 02 Nov 2019)" );
	script_name( "Debian Security Advisory DSA 4557-1 (libarchive - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|10)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4557.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4557-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libarchive'
  package(s) announced via the DSA-4557-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A use-after-free was found in libarchive, a multi-format archive and
compression library, which could result in denial of service and
potentially the execution of arbitrary code is a malformed archive
is processed." );
	script_tag( name: "affected", value: "'libarchive' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), this problem has been fixed
in version 3.2.2-2+deb9u2.

For the stable distribution (buster), this problem has been fixed in
version 3.3.3-4+deb10u1.

We recommend that you upgrade your libarchive packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "bsdcpio", ver: "3.2.2-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bsdtar", ver: "3.2.2-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libarchive-dev", ver: "3.2.2-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libarchive-tools", ver: "3.2.2-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libarchive13", ver: "3.2.2-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bsdcpio", ver: "3.3.3-4+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bsdtar", ver: "3.3.3-4+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libarchive-dev", ver: "3.3.3-4+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libarchive-tools", ver: "3.3.3-4+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libarchive13", ver: "3.3.3-4+deb10u1", rls: "DEB10" ) )){
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
