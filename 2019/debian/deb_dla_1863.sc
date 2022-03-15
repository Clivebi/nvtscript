if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891863" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-13272" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-02 15:42:00 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-07-24 02:00:11 +0000 (Wed, 24 Jul 2019)" );
	script_name( "Debian LTS: Security Advisory for linux-4.9 (DLA-1863-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/07/msg00023.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1863-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-4.9'
  package(s) announced via the DLA-1863-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Jann Horn discovered that the ptrace subsystem in the Linux kernel
mishandles the management of the credentials of a process that wants
to create a ptrace relationship, allowing a local user to obtain root
privileges under certain scenarios." );
	script_tag( name: "affected", value: "'linux-4.9' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
4.9.168-1+deb9u4~deb8u1.

We recommend that you upgrade your linux-4.9 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-4.9-arm", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-doc-4.9", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-686", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-686-pae", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-all", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-all-amd64", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-all-armel", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-all-armhf", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-all-i386", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-amd64", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-armmp", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-armmp-lpae", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-common", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-common-rt", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-marvell", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-rt-686-pae", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-rt-amd64", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.8-686", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.8-686-pae", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.8-all", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.8-all-amd64", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.8-all-armel", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.8-all-armhf", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.8-all-i386", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.8-amd64", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.8-armmp", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.8-armmp-lpae", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.8-common", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.8-common-rt", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.8-marvell", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.8-rt-686-pae", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.8-rt-amd64", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.9-686", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.9-686-pae", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.9-all", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.9-all-amd64", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.9-all-armel", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.9-all-armhf", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.9-all-i386", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.9-amd64", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.9-armmp", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.9-armmp-lpae", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.9-common", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.9-common-rt", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.9-marvell", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.9-rt-686-pae", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.9-rt-amd64", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-686", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-686-pae", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-686-pae-dbg", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-amd64", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-amd64-dbg", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-armmp", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-armmp-lpae", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-marvell", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-rt-686-pae", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-rt-686-pae-dbg", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-rt-amd64", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-rt-amd64-dbg", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.8-686", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.8-686-pae", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.8-686-pae-dbg", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.8-amd64", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.8-amd64-dbg", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.8-armmp", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.8-armmp-lpae", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.8-marvell", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.8-rt-686-pae", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.8-rt-686-pae-dbg", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.8-rt-amd64", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.8-rt-amd64-dbg", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.9-686", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.9-686-pae", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.9-686-pae-dbg", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.9-amd64", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.9-amd64-dbg", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.9-armmp", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.9-armmp-lpae", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.9-marvell", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.9-rt-686-pae", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.9-rt-686-pae-dbg", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.9-rt-amd64", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.9-rt-amd64-dbg", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-kbuild-4.9", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-manual-4.9", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-perf-4.9", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-source-4.9", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-4.9.0-0.bpo.7", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-4.9.0-0.bpo.8", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-4.9.0-0.bpo.9", ver: "4.9.168-1+deb9u4~deb8u1", rls: "DEB8" ) )){
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

