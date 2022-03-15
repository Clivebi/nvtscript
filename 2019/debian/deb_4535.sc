if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704535" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2019-5094" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-11 19:21:00 +0000 (Mon, 11 Jan 2021)" );
	script_tag( name: "creation_date", value: "2019-09-28 02:00:08 +0000 (Sat, 28 Sep 2019)" );
	script_name( "Debian Security Advisory DSA 4535-1 (e2fsprogs - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|10)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4535.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4535-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'e2fsprogs'
  package(s) announced via the DSA-4535-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Lilith of Cisco Talos discovered a buffer overflow flaw in the quota
code used by e2fsck from the ext2/ext3/ext4 file system utilities.
Running e2fsck on a malformed file system can result in the execution of
arbitrary code." );
	script_tag( name: "affected", value: "'e2fsprogs' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), this problem has been fixed
in version 1.43.4-2+deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 1.44.5-1+deb10u2.

We recommend that you upgrade your e2fsprogs packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "e2fsck-static", ver: "1.43.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "e2fslibs", ver: "1.43.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "e2fslibs-dev", ver: "1.43.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "e2fsprogs", ver: "1.43.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "fuse2fs", ver: "1.43.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcomerr2", ver: "1.43.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libss2", ver: "1.43.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "e2fsck-static", ver: "1.44.5-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "e2fslibs", ver: "1.44.5-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "e2fslibs-dev", ver: "1.44.5-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "e2fsprogs", ver: "1.44.5-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "e2fsprogs-l10n", ver: "1.44.5-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "fuse2fs", ver: "1.44.5-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcom-err2", ver: "1.44.5-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcomerr2", ver: "1.44.5-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libext2fs-dev", ver: "1.44.5-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libext2fs2", ver: "1.44.5-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libss2", ver: "1.44.5-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "comerr-dev", ver: "2.1-1.43.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ss-dev", ver: "2.0-1.43.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "comerr-dev", ver: "2.1-1.44.5-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ss-dev", ver: "2.0-1.44.5-1+deb10u2", rls: "DEB10" ) )){
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

