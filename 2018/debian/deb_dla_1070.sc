if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891070" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2017-10664", "CVE-2017-11434", "CVE-2017-6505", "CVE-2017-8309" );
	script_name( "Debian LTS: Security Advisory for qemu (DLA-1070-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-10 17:20:00 +0000 (Thu, 10 Sep 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/08/msg00023.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "qemu on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.1.2+dfsg-6+deb7u23.

We recommend that you upgrade your qemu packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities were discovered in qemu, a fast processor
emulator. The Common Vulnerabilities and Exposures project identifies
the following problems:

CVE-2017-6505

Denial of service via infinite loop in the USB OHCI emulation

CVE-2017-8309

Denial of service via VNC audio capture

CVE-2017-10664

Denial of service in qemu-nbd server, qemu-io and qemu-img

CVE-2017-11434

Denial of service via a crafted DHCP options string" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "qemu", ver: "1.1.2+dfsg-6+deb7u23", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-keymaps", ver: "1.1.2+dfsg-6+deb7u23", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system", ver: "1.1.2+dfsg-6+deb7u23", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-user", ver: "1.1.2+dfsg-6+deb7u23", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-user-static", ver: "1.1.2+dfsg-6+deb7u23", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-utils", ver: "1.1.2+dfsg-6+deb7u23", rls: "DEB7" ) )){
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

