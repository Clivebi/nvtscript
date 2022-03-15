if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892039" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2017-11333", "CVE-2017-14633" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-12-18 03:00:49 +0000 (Wed, 18 Dec 2019)" );
	script_name( "Debian LTS: Security Advisory for libvorbis (DLA-2039-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/12/msg00021.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2039-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvorbis'
  package(s) announced via the DLA-2039-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two issues have been found in libvorbis, a decoder library for Vorbis
General Audio Compression Codec.

2017-14633

In Xiph.Org libvorbis 1.3.5, an out-of-bounds array read
vulnerability exists in the function mapping0_forward() in
mapping0.c, which may lead to DoS when operating on a crafted
audio file with vorbis_analysis().

2017-11333

The vorbis_analysis_wrote function in lib/block.c in Xiph.Org
libvorbis 1.3.5 allows remote attackers to cause a denial of
service (OOM) via a crafted wav file." );
	script_tag( name: "affected", value: "'libvorbis' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.3.4-2+deb8u3.

We recommend that you upgrade your libvorbis packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libvorbis-dbg", ver: "1.3.4-2+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvorbis-dev", ver: "1.3.4-2+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvorbis0a", ver: "1.3.4-2+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvorbisenc2", ver: "1.3.4-2+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvorbisfile3", ver: "1.3.4-2+deb8u3", rls: "DEB8" ) )){
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

