if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703285" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-3209", "CVE-2015-4037" );
	script_name( "Debian Security Advisory DSA 3285-1 (qemu-kvm - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-06-13 00:00:00 +0200 (Sat, 13 Jun 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3285.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "qemu-kvm on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 1.1.2+dfsg-6+deb7u8.

We recommend that you upgrade your qemu-kvm packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered
in qemu-kvm, a full virtualization solution on x86 hardware.

CVE-2015-3209
Matt Tait of Google's Project Zero security team discovered a flaw
in the way QEMU's AMD PCnet Ethernet emulation handles multi-TMD
packets with a length above 4096 bytes. A privileged guest user in a
guest with an AMD PCNet ethernet card enabled can potentially use
this flaw to execute arbitrary code on the host with the privileges
of the hosting QEMU process.

CVE-2015-4037
Kurt Seifried of Red Hat Product Security discovered that QEMU's
user mode networking stack uses predictable temporary file names
when the -smb option is used. An unprivileged user can use this flaw
to cause a denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "kvm", ver: "1.1.2+dfsg-6+deb7u8", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-kvm", ver: "1.1.2+dfsg-6+deb7u8", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-kvm-dbg", ver: "1.1.2+dfsg-6+deb7u8", rls: "DEB7" ) ) != NULL){
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

