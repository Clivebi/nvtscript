if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890956" );
	script_version( "2021-06-16T11:00:23+0000" );
	script_cve_id( "CVE-2017-8361", "CVE-2017-8362", "CVE-2017-8363", "CVE-2017-8365" );
	script_name( "Debian LTS: Security Advisory for libsndfile (DLA-956-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-25 00:00:00 +0100 (Thu, 25 Jan 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-05 17:43:00 +0000 (Tue, 05 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/05/msg00027.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libsndfile on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.0.25-9.1+deb7u2.

We recommend that you upgrade your libsndfile packages." );
	script_tag( name: "summary", value: "CVE-2017-8361
The flac_buffer_copy function in flac.c in libsndfile 1.0.28 allows
remote attackers to cause a denial of service (buffer overflow and
application crash) or possibly have unspecified other impact via a
crafted audio file.

CVE-2017-8362
The flac_buffer_copy function in flac.c in libsndfile 1.0.28 allows
remote attackers to cause a denial of service (invalid read and
application crash) via a crafted audio file.

CVE-2017-8363
The flac_buffer_copy function in flac.c in libsndfile 1.0.28 allows
remote attackers to cause a denial of service (heap-based buffer
over-read and application crash) via a crafted audio file.

CVE-2017-8365
The i2les_array function in pcm.c in libsndfile 1.0.28 allows
remote attackers to cause a denial of service (buffer over-read
and application crash) via a crafted audio file." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libsndfile1", ver: "1.0.25-9.1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsndfile1-dev", ver: "1.0.25-9.1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sndfile-programs", ver: "1.0.25-9.1+deb7u2", rls: "DEB7" ) )){
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

