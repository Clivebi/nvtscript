if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892716" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2020-35653", "CVE-2021-25290", "CVE-2021-28676", "CVE-2021-28677", "CVE-2021-34552" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-16 12:28:00 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-23 03:00:13 +0000 (Fri, 23 Jul 2021)" );
	script_name( "Debian LTS: Security Advisory for pillow (DLA-2716-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/07/msg00018.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2716-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2716-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/991293" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pillow'
  package(s) announced via the DLA-2716-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in pillow (Python Imaging
Library - PIL).

Affected binary packages:

python-imaging
python-pil-dbg
python-pil-doc
python-pil.imagetk-dbg
python-pil.imagetk
python-pil
python3-pil-dbg
python3-pil.imagetk-dbg
python3-pil.imagetk
python3-pil

CVE-2020-35653

Pillow through 8.2.0 and PIL (aka Python Imaging Library) through
1.1.7 allow an attacker to pass controlled parameters directly into
a convert function to trigger a buffer overflow in Convert.c.

CVE-2021-25290

An issue was discovered in Pillow before 8.1.1. In TiffDecode.c,
there is a negative-offset memcpy with an invalid size.

CVE-2021-28676

An issue was discovered in Pillow before 8.2.0. For FLI data,
FliDecode did not properly check that the block advance was
non-zero, potentially leading to an infinite loop on load.

CVE-2021-28677

An issue was discovered in Pillow before 8.2.0. For EPS data, the
readline implementation used in EPSImageFile has to deal with any
combination of \\r and \\n as line endings. It used an accidentally
quadratic method of accumulating lines while looking for a line
ending. A malicious EPS file could use this to perform a DoS of
Pillow in the open phase, before an image was accepted for opening.

CVE-2021-34552

Pillow through 8.2.0 and PIL (aka Python Imaging Library) through
1.1.7 allow an attacker to pass controlled parameters directly into
a convert function to trigger a buffer overflow in Convert.c." );
	script_tag( name: "affected", value: "'pillow' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
4.0.0-4+deb9u3.

We recommend that you upgrade your pillow packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-imaging", ver: "4.0.0-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-pil", ver: "4.0.0-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-pil-dbg", ver: "4.0.0-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-pil-doc", ver: "4.0.0-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-pil.imagetk", ver: "4.0.0-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-pil.imagetk-dbg", ver: "4.0.0-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-pil", ver: "4.0.0-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-pil-dbg", ver: "4.0.0-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-pil.imagetk", ver: "4.0.0-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-pil.imagetk-dbg", ver: "4.0.0-4+deb9u3", rls: "DEB9" ) )){
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

