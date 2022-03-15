if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891690" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2019-6256", "CVE-2019-7314" );
	script_name( "Debian LTS: Security Advisory for liblivemedia (DLA-1690-1)" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-26 00:00:00 +0100 (Tue, 26 Feb 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/02/msg00037.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "liblivemedia on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2014.01.13-1+deb8u2.

We recommend that you upgrade your liblivemedia packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in liblivemedia, the
LIVE555 RTSP server library:

CVE-2019-6256

liblivemedia servers with RTSP-over-HTTP tunneling enabled are
vulnerable to an invalid function pointer dereference. This issue
might happen during error handling when processing two GET and
POST requests being sent with identical x-sessioncookie within
the same TCP session and might be leveraged by remote attackers
to cause DoS.

CVE-2019-7314

liblivemedia servers with RTSP-over-HTTP tunneling enabled are
affected by a use-after-free vulnerability. This vulnerability
might be triggered by remote attackers to cause DoS (server crash)
or possibly unspecified other impact." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libbasicusageenvironment0", ver: "2014.01.13-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgroupsock1", ver: "2014.01.13-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblivemedia-dev", ver: "2014.01.13-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblivemedia23", ver: "2014.01.13-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libusageenvironment1", ver: "2014.01.13-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "livemedia-utils", ver: "2014.01.13-1+deb8u2", rls: "DEB8" ) )){
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

