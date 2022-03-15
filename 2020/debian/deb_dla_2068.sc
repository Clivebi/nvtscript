if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892068" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2019-10220", "CVE-2019-14895", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-14901", "CVE-2019-15098", "CVE-2019-15217", "CVE-2019-15291", "CVE-2019-15505", "CVE-2019-16746", "CVE-2019-17052", "CVE-2019-17053", "CVE-2019-17054", "CVE-2019-17055", "CVE-2019-17056", "CVE-2019-17133", "CVE-2019-17666", "CVE-2019-19051", "CVE-2019-19052", "CVE-2019-19056", "CVE-2019-19057", "CVE-2019-19062", "CVE-2019-19066", "CVE-2019-19227", "CVE-2019-19332", "CVE-2019-19523", "CVE-2019-19524", "CVE-2019-19527", "CVE-2019-19530", "CVE-2019-19531", "CVE-2019-19532", "CVE-2019-19533", "CVE-2019-19534", "CVE-2019-19536", "CVE-2019-19537", "CVE-2019-19767", "CVE-2019-19922", "CVE-2019-19947", "CVE-2019-19965", "CVE-2019-19966", "CVE-2019-2215" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-03 11:15:00 +0000 (Fri, 03 Jan 2020)" );
	script_tag( name: "creation_date", value: "2020-01-19 04:00:44 +0000 (Sun, 19 Jan 2020)" );
	script_name( "Debian LTS: Security Advisory for linux (DLA-2068-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/01/msg00013.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2068-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the DLA-2068-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service, or information
leak.

CVE-2019-2215

The syzkaller tool discovered a use-after-free vulnerability in
the Android binder driver. A local user on a system with this
driver enabled could use this to cause a denial of service (memory
corruption or crash) or possibly for privilege escalation.
However, this driver is not enabled on Debian packaged kernels.

CVE-2019-10220

Various developers and researchers found that if a crafted file-
system or malicious file server presented a directory with
filenames including a '/' character, this could confuse and
possibly defeat security checks in applications that read the
directory.

The kernel will now return an error when reading such a directory,
rather than passing the invalid filenames on to user-space.

CVE-2019-14895, CVE-2019-14901

ADLab of Venustech discovered potential heap buffer overflows in
the mwifiex wifi driver. On systems using this driver, a
malicious Wireless Access Point or adhoc/P2P peer could use these
to cause a denial of service (memory corruption or crash) or
possibly for remote code execution.

CVE-2019-14896, CVE-2019-14897

ADLab of Venustech discovered potential heap and stack buffer
overflows in the libertas wifi driver. On systems using this
driver, a malicious Wireless Access Point or adhoc/P2P peer could
use these to cause a denial of service (memory corruption or
crash) or possibly for remote code execution.

CVE-2019-15098

Hui Peng and Mathias Payer reported that the ath6kl wifi driver
did not properly validate USB descriptors, which could lead to a
null pointer dereference. An attacker able to add USB devices
could use this to cause a denial of service (BUG/oops).

CVE-2019-15217

The syzkaller tool discovered that the zr364xx mdia driver did not
correctly handle devices without a product name string, which
could lead to a null pointer dereference. An attacker able to add
USB devices could use this to cause a denial of service
(BUG/oops).

CVE-2019-15291

The syzkaller tool discovered that the b2c2-flexcop-usb media
driver did not properly validate USB descriptors, which could lead
to a null pointer dereference. An attacker able to add USB
devices could use this to cause a denial of service (BUG/oops).

CVE-2019-15505

The syzkaller tool discovered that the technisat-usb2 media driver
did not properly validate incoming IR packets, which could lead to
a heap buffer over-read. An attacker able to add USB devices
could use this to cause a denial of service (BUG/oops) or to read
sensitive information from kernel memory.

 ...

  Description truncated. Please see the references for more information." );
	script_tag( name: "affected", value: "'linux' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.16.81-1.

We recommend that you upgrade your linux packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-4.8-arm", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-4.9-x86", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-doc-3.16", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-586", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-686-pae", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-all", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-all-amd64", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-all-armel", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-all-armhf", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-all-i386", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-amd64", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-armmp", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-armmp-lpae", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-common", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-ixp4xx", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-kirkwood", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-orion5x", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-versatile", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-10-586", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-10-686-pae", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-10-686-pae-dbg", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-10-amd64", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-10-amd64-dbg", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-10-armmp", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-10-armmp-lpae", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-10-ixp4xx", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-10-kirkwood", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-10-orion5x", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-10-versatile", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-libc-dev", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-manual-3.16", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-source-3.16", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-3.16.0-10", ver: "3.16.81-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.16.0-10-amd64", ver: "3.16.81-1", rls: "DEB8" ) )){
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

