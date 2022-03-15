if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71492" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-0217" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:13:49 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Debian Security Advisory DSA 2508-1 (kfreebsd-8)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202508-1" );
	script_tag( name: "insight", value: "Rafal Wojtczuk from Bromium discovered that FreeBSD wasn't handling correctly
uncanonical return addresses on Intel amd64 CPUs, allowing privilege escalation
to kernel for local users.

For the stable distribution (squeeze), this problem has been fixed in
version 8.1+dfsg-8+squeeze3.

For the testing distribution (wheezy), this problem has been fixed in
version 8.3-4.

For the unstable distribution (sid), this problem has been fixed in
version 8.3-4." );
	script_tag( name: "solution", value: "We recommend that you upgrade your kfreebsd-8 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to kfreebsd-8
announced via advisory DSA 2508-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8-486", ver: "8.1+dfsg-8+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8-686", ver: "8.1+dfsg-8+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8-686-smp", ver: "8.1+dfsg-8+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8-amd64", ver: "8.1+dfsg-8+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8.1-1", ver: "8.1+dfsg-8+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8.1-1-486", ver: "8.1+dfsg-8+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8.1-1-686", ver: "8.1+dfsg-8+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8.1-1-686-smp", ver: "8.1+dfsg-8+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8.1-1-amd64", ver: "8.1+dfsg-8+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8-486", ver: "8.1+dfsg-8+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8-686", ver: "8.1+dfsg-8+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8-686-smp", ver: "8.1+dfsg-8+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8-amd64", ver: "8.1+dfsg-8+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8.1-1-486", ver: "8.1+dfsg-8+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8.1-1-686", ver: "8.1+dfsg-8+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8.1-1-686-smp", ver: "8.1+dfsg-8+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8.1-1-amd64", ver: "8.1+dfsg-8+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-source-8.1", ver: "8.1+dfsg-8+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "acpi-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "acpi-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cdrom-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cdrom-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "crypto-dm-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "crypto-dm-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "crypto-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "crypto-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ext2-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ext2-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "fat-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "fat-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "floppy-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "floppy-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "i2c-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "i2c-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ipv6-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ipv6-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isofs-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isofs-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kernel-image-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kernel-image-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8-486", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8-686", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8-686-smp", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8-amd64", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8-malta", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8-xen", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8.3-1", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8.3-1-486", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8.3-1-686", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8.3-1-686-smp", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8.3-1-amd64", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8.3-1-malta", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8.3-1-xen", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8-486", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8-686", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8-686-smp", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8-amd64", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8-malta", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8-xen", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8.3-1-486", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8.3-1-686", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8.3-1-686-smp", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8.3-1-amd64", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8.3-1-malta", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8.3-1-xen", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-source-8.3", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "loop-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "loop-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "md-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "md-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mmc-core-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mmc-core-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mmc-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mmc-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nfs-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nfs-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nic-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nic-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nic-shared-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nic-shared-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nic-wireless-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nic-wireless-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nls-core-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nls-core-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntfs-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntfs-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nullfs-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nullfs-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "parport-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "parport-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "plip-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "plip-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ppp-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ppp-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "reiserfs-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "reiserfs-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "sata-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "sata-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "scsi-core-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "scsi-core-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "scsi-extra-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "scsi-extra-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "scsi-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "scsi-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "serial-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "serial-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "sound-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "sound-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xfs-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xfs-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zfs-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zfs-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zlib-modules-8.3-1-486-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zlib-modules-8.3-1-amd64-di", ver: "8.3-4", rls: "DEB7" ) ) != NULL){
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

