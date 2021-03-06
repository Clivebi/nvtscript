if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703259" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2014-9718", "CVE-2015-1779", "CVE-2015-2756", "CVE-2015-3456" );
	script_name( "Debian Security Advisory DSA 3259-1 (qemu - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-05-13 00:00:00 +0200 (Wed, 13 May 2015)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3259.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "qemu on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 1.1.2+dfsg-6a+deb7u7 of the qemu source
package and in version 1.1.2+dfsg-6+deb7u7 of the qemu-kvm source package. Only
CVE-2015-3456 affects oldstable.

For the stable distribution (jessie), these problems have been fixed in
version 1:2.1+dfsg-12.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your qemu packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered
in the qemu virtualisation solution:

CVE-2014-9718
It was discovered that the IDE controller emulation is susceptible
to denial of service.

CVE-2015-1779
Daniel P. Berrange discovered a denial of service vulnerability in
the VNC web socket decoder.

CVE-2015-2756
Jan Beulich discovered that unmediated PCI command register could
result in denial of service.

CVE-2015-3456
Jason Geffner discovered a buffer overflow in the emulated floppy
disk drive, resulting in the potential execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "kvm", ver: "1.1.2+dfsg-6+deb7u7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-kvm", ver: "1.1.2+dfsg-6+deb7u7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-kvm-dbg", ver: "1.1.2+dfsg-6+deb7u7", rls: "DEB7" ) ) != NULL){
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

