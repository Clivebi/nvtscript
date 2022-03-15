if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891808" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-8354", "CVE-2019-8355", "CVE-2019-8356", "CVE-2019-8357" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-29 02:00:09 +0000 (Wed, 29 May 2019)" );
	script_name( "Debian LTS: Security Advisory for sox (DLA-1808-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/05/msg00040.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1808-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/927906" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sox'
  package(s) announced via the DLA-1808-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several issues were found in SoX, the Swiss army knife of sound processing
programs, that could lead to denial of service via application crash or
potentially to arbitrary code execution by processing maliciously crafted
input files." );
	script_tag( name: "affected", value: "'sox' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
14.4.1-5+deb8u4.

We recommend that you upgrade your sox packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libsox-dev", ver: "14.4.1-5+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-all", ver: "14.4.1-5+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-alsa", ver: "14.4.1-5+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-ao", ver: "14.4.1-5+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-base", ver: "14.4.1-5+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-mp3", ver: "14.4.1-5+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-oss", ver: "14.4.1-5+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-pulse", ver: "14.4.1-5+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox2", ver: "14.4.1-5+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sox", ver: "14.4.1-5+deb8u4", rls: "DEB8" ) )){
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

