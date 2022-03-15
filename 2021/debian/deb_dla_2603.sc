if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892603" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2019-11372", "CVE-2019-11373", "CVE-2020-15395", "CVE-2020-26797" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-17 03:15:00 +0000 (Tue, 17 Nov 2020)" );
	script_tag( name: "creation_date", value: "2021-03-24 04:00:14 +0000 (Wed, 24 Mar 2021)" );
	script_name( "Debian LTS: Security Advisory for libmediainfo (DLA-2603-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/03/msg00029.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2603-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2603-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/927672" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libmediainfo'
  package(s) announced via the DLA-2603-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there were a number of vulnerabilities in
libmediainfo, a library reading metadata such as track names,
lengths, etc. from media files." );
	script_tag( name: "affected", value: "'libmediainfo' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', these problems have been fixed in version
0.7.91-1+deb9u1.

We recommend that you upgrade your libmediainfo packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmediainfo-dev", ver: "0.7.91-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmediainfo-doc", ver: "0.7.91-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmediainfo0v5", ver: "0.7.91-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-mediainfodll", ver: "0.7.91-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-mediainfodll", ver: "0.7.91-1+deb9u1", rls: "DEB9" ) )){
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

