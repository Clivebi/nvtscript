if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704512" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2019-13164", "CVE-2019-14378" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-09-03 02:00:06 +0000 (Tue, 03 Sep 2019)" );
	script_name( "Debian Security Advisory DSA 4512-1 (qemu - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4512.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4512-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu'
  package(s) announced via the DSA-4512-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were discovered in QEMU, a fast processor
emulator, which could result in denial of service, the execution of
arbitrary code or bypass of ACLs." );
	script_tag( name: "affected", value: "'qemu' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 1:3.1+dfsg-8+deb10u2.

We recommend that you upgrade your qemu packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "qemu", ver: "1:3.1+dfsg-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-block-extra", ver: "1:3.1+dfsg-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-guest-agent", ver: "1:3.1+dfsg-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-kvm", ver: "1:3.1+dfsg-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system", ver: "1:3.1+dfsg-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:3.1+dfsg-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-common", ver: "1:3.1+dfsg-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-data", ver: "1:3.1+dfsg-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-gui", ver: "1:3.1+dfsg-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:3.1+dfsg-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:3.1+dfsg-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:3.1+dfsg-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:3.1+dfsg-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:3.1+dfsg-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-user", ver: "1:3.1+dfsg-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-user-binfmt", ver: "1:3.1+dfsg-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-user-static", ver: "1:3.1+dfsg-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-utils", ver: "1:3.1+dfsg-8+deb10u2", rls: "DEB10" ) )){
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

