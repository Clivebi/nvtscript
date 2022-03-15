if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890928" );
	script_version( "2020-11-24T09:37:13+0000" );
	script_cve_id( "CVE-2014-9496", "CVE-2014-9756", "CVE-2015-7805", "CVE-2017-7585", "CVE-2017-7586", "CVE-2017-7741", "CVE-2017-7742" );
	script_name( "Debian LTS: Security Advisory for libsndfile (DLA-928-1)" );
	script_tag( name: "last_modification", value: "2020-11-24 09:37:13 +0000 (Tue, 24 Nov 2020)" );
	script_tag( name: "creation_date", value: "2018-01-17 00:00:00 +0100 (Wed, 17 Jan 2018)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/04/msg00047.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libsndfile on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.0.25-9.1+deb7u1.

We recommend that you upgrade your libsndfile packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities were found in libsndfile, a popular library
for reading/writing audio files.

CVE-2017-7585

In libsndfile before 1.0.28, an error in the 'flac_buffer_copy()'
function (flac.c) can be exploited to cause a stack-based buffer
overflow via a specially crafted FLAC file.

CVE-2017-7586

In libsndfile before 1.0.28, an error in the 'header_read()'
function (common.c) when handling ID3 tags can be exploited to
cause a stack-based buffer overflow via a specially crafted FLAC
file.

CVE-2017-7741

In libsndfile before 1.0.28, an error in the 'flac_buffer_copy()'
function (flac.c) can be exploited to cause a segmentation
violation (with write memory access) via a specially crafted FLAC
file during a resample attempt, a similar issue to CVE-2017-7585.

CVE-2017-7742

In libsndfile before 1.0.28, an error in the 'flac_buffer_copy()'
function (flac.c) can be exploited to cause a segmentation
violation (with read memory access) via a specially crafted FLAC
file during a resample attempt, a similar issue to
CVE-2017-7585.

CVE-2014-9496

The sd2_parse_rsrc_fork function in sd2.c in libsndfile allows
attackers to have unspecified impact via vectors related to a (1)
map offset or (2) rsrc marker, which triggers an out-of-bounds
read.

CVE-2014-9756

The psf_fwrite function in file_io.c in libsndfile allows
attackers to cause a denial of service (divide-by-zero error and
application crash) via unspecified vectors related to the
headindex variable.

CVE-2015-7805

Heap-based buffer overflow in libsndfile 1.0.25 allows remote
attackers to have unspecified impact via the headindex value in
the header in an AIFF file." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libsndfile1", ver: "1.0.25-9.1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsndfile1-dev", ver: "1.0.25-9.1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sndfile-programs", ver: "1.0.25-9.1+deb7u1", rls: "DEB7" ) )){
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

