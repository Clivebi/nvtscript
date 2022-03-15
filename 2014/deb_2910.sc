if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702910" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-0150" );
	script_name( "Debian Security Advisory DSA 2910-1 (qemu-kvm - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-04-18 00:00:00 +0200 (Fri, 18 Apr 2014)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:S/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2910.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "qemu-kvm on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 0.12.5+dfsg-5+squeeze11.

For the stable distribution (wheezy), this problem has been fixed in
version 1.1.2+dfsg-6+deb7u1.

We recommend that you upgrade your qemu-kvm packages." );
	script_tag( name: "summary", value: "Michael S. Tsirkin of Red Hat discovered a buffer overflow flaw in the
way qemu processed MAC addresses table update requests from the guest.

A privileged guest user could use this flaw to corrupt qemu process
memory on the host, which could potentially result in arbitrary code
execution on the host with the privileges of the qemu process." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "kvm", ver: "0.12.5+dfsg-5+squeeze11", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-kvm", ver: "0.12.5+dfsg-5+squeeze11", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-kvm-dbg", ver: "0.12.5+dfsg-5+squeeze11", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kvm", ver: "1.1.2+dfsg-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-kvm", ver: "1.1.2+dfsg-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-kvm-dbg", ver: "1.1.2+dfsg-6+deb7u1", rls: "DEB7" ) ) != NULL){
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

