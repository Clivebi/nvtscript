if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892168" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2017-5209", "CVE-2017-5545", "CVE-2017-5834", "CVE-2017-5835", "CVE-2017-6435", "CVE-2017-6436", "CVE-2017-6439", "CVE-2017-7982" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-02 10:15:00 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-04-03 03:00:20 +0000 (Fri, 03 Apr 2020)" );
	script_name( "Debian LTS: Security Advisory for libplist (DLA-2168-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/04/msg00002.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2168-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/851196" );
	script_xref( name: "URL", value: "https://bugs.debian.org/852385" );
	script_xref( name: "URL", value: "https://bugs.debian.org/854000" );
	script_xref( name: "URL", value: "https://bugs.debian.org/860945" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libplist'
  package(s) announced via the DLA-2168-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "libplist is a library for reading and writing the Apple binary and XML
property lists format. It's part of the libimobiledevice stack, providing
access to iDevices (iPod, iPhone, iPad ...).

CVE-2017-5209

The base64decode function in base64.c allows attackers to obtain sensitive
information from process memory or cause a denial of service (buffer
over-read) via split encoded Apple Property List data.

CVE-2017-5545

The main function in plistutil.c allows attackers to obtain sensitive
information from process memory or cause a denial of service (buffer
over-read) via Apple Property List data that is too short.

CVE-2017-5834

The parse_dict_node function in bplist.c allows attackers to cause a denial
of service (out-of-bounds heap read and crash) via a crafted file.

CVE-2017-5835

libplist allows attackers to cause a denial of service (large memory
allocation and crash) via vectors involving an offset size of zero.

CVE-2017-6435

The parse_string_node function in bplist.c allows local users to cause a
denial of service (memory corruption) via a crafted plist file.

CVE-2017-6436

The parse_string_node function in bplist.c allows local users to cause a
denial of service (memory allocation error) via a crafted plist file.

CVE-2017-6439

Heap-based buffer overflow in the parse_string_node function in bplist.c
allows local users to cause a denial of service (out-of-bounds write) via
a crafted plist file.

CVE-2017-7982

Integer overflow in the plist_from_bin function in bplist.c allows remote
attackers to cause a denial of service (heap-based buffer over-read and
application crash) via a crafted plist file." );
	script_tag( name: "affected", value: "'libplist' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.11-3+deb8u1.

We recommend that you upgrade your libplist packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libplist++-dev", ver: "1.11-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libplist++2", ver: "1.11-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libplist-dbg", ver: "1.11-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libplist-dev", ver: "1.11-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libplist-doc", ver: "1.11-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libplist-utils", ver: "1.11-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libplist2", ver: "1.11-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-plist", ver: "1.11-3+deb8u1", rls: "DEB8" ) )){
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

