if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704338" );
	script_version( "2021-06-17T04:16:32+0000" );
	script_cve_id( "CVE-2018-10839", "CVE-2018-17962", "CVE-2018-17963" );
	script_name( "Debian Security Advisory DSA 4338-1 (qemu - security update)" );
	script_tag( name: "last_modification", value: "2021-06-17 04:16:32 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-11 00:00:00 +0100 (Sun, 11 Nov 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-14 15:00:00 +0000 (Thu, 14 May 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4338.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "qemu on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 1:2.8+dfsg-6+deb9u5.

We recommend that you upgrade your qemu packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/qemu" );
	script_tag( name: "summary", value: "Integer overflows in the processing of packets in network cards emulated
by QEMU, a fast processor emulator, could result in denial of service.

In addition this update backports support to passthrough the new CPU
features added in the intel-microcode update shipped in DSA 4273 to
x86-based guests." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "qemu", ver: "1:2.8+dfsg-6+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-block-extra", ver: "1:2.8+dfsg-6+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-guest-agent", ver: "1:2.8+dfsg-6+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-kvm", ver: "1:2.8+dfsg-6+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system", ver: "1:2.8+dfsg-6+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:2.8+dfsg-6+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-common", ver: "1:2.8+dfsg-6+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:2.8+dfsg-6+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:2.8+dfsg-6+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:2.8+dfsg-6+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:2.8+dfsg-6+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:2.8+dfsg-6+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-user", ver: "1:2.8+dfsg-6+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-user-binfmt", ver: "1:2.8+dfsg-6+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-user-static", ver: "1:2.8+dfsg-6+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-utils", ver: "1:2.8+dfsg-6+deb9u5", rls: "DEB9" ) )){
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

