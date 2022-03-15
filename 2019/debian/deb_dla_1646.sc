if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891646" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2018-17958", "CVE-2018-19364", "CVE-2018-19489" );
	script_name( "Debian LTS: Security Advisory for qemu (DLA-1646-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-30 00:00:00 +0100 (Wed, 30 Jan 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-10 17:11:00 +0000 (Thu, 10 Sep 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/01/msg00023.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "qemu on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1:2.1+dfsg-12+deb8u9.

We recommend that you upgrade your qemu packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were found in QEMU, a fast processor emulator:

CVE-2018-17958

The rtl8139 emulator is affected by an integer overflow and subsequent
buffer overflow. This vulnerability might be triggered by remote
attackers with crafted packets to perform denial of service (via OOB
stack buffer access).

CVE-2018-19364

The 9pfs subsystem is affected by a race condition allowing threads to
modify an fid path while it is being accessed by another thread,
leading to (for example) a use-after-free outcome. This vulnerability
might be triggered by local attackers to perform denial of service.

CVE-2018-19489

The 9pfs subsystem is affected by a race condition during file
renaming. This vulnerability might be triggered by local attackers to
perform denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "qemu", ver: "1:2.1+dfsg-12+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-guest-agent", ver: "1:2.1+dfsg-12+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-kvm", ver: "1:2.1+dfsg-12+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system", ver: "1:2.1+dfsg-12+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:2.1+dfsg-12+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-common", ver: "1:2.1+dfsg-12+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:2.1+dfsg-12+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:2.1+dfsg-12+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:2.1+dfsg-12+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:2.1+dfsg-12+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:2.1+dfsg-12+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-user", ver: "1:2.1+dfsg-12+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-user-binfmt", ver: "1:2.1+dfsg-12+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-user-static", ver: "1:2.1+dfsg-12+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-utils", ver: "1:2.1+dfsg-12+deb8u9", rls: "DEB8" ) )){
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

