if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891695" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2017-15370", "CVE-2017-15372", "CVE-2017-15642", "CVE-2017-18189" );
	script_name( "Debian LTS: Security Advisory for sox (DLA-1695-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-28 00:00:00 +0100 (Thu, 28 Feb 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-24 15:16:00 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/02/msg00042.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "sox on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
14.4.1-5+deb8u2.

We recommend that you upgrade your sox packages." );
	script_tag( name: "summary", value: ", 878810, 882144, 881121

Multiple vulnerabilities have been discovered in SoX (Sound eXchange),
a sound processing program:

CVE-2017-15370

The ImaAdpcmReadBlock function (src/wav.c) is affected by a heap buffer
overflow. This vulnerability might be leveraged by remote attackers
using a crafted WAV file to cause denial of service (application crash).

CVE-2017-15372

The lsx_ms_adpcm_block_expand_i function (adpcm.c) is affected by a
stack based buffer overflow. This vulnerability might be leveraged by
remote attackers using a crafted audio file to cause denial of service
(application crash).

CVE-2017-15642

The lsx_aiffstartread function (aiff.c) is affected by a use-after-free
vulnerability. This flaw might be leveraged by remote attackers using a
crafted AIFF file to cause denial of service (application crash).

CVE-2017-18189

The startread function (xa.c) is affected by a null pointer dereference
vulnerability. This flaw might be leveraged by remote attackers using a
crafted Maxis XA audio file to cause denial of service (application
crash)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libsox-dev", ver: "14.4.1-5+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-all", ver: "14.4.1-5+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-alsa", ver: "14.4.1-5+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-ao", ver: "14.4.1-5+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-base", ver: "14.4.1-5+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-mp3", ver: "14.4.1-5+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-oss", ver: "14.4.1-5+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-pulse", ver: "14.4.1-5+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox2", ver: "14.4.1-5+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sox", ver: "14.4.1-5+deb8u2", rls: "DEB8" ) )){
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

