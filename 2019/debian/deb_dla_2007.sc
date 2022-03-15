if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892007" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2017-17742", "CVE-2019-15845", "CVE-2019-16201", "CVE-2019-16254", "CVE-2019-16255" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-16 15:15:00 +0000 (Sun, 16 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-11-26 12:50:25 +0000 (Tue, 26 Nov 2019)" );
	script_name( "Debian LTS: Security Advisory for ruby2.1 (DLA-2007-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/11/msg00025.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2007-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby2.1'
  package(s) announced via the DLA-2007-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several flaws have been found in ruby2.1, an interpreter of an
object-oriented scripting language.

CVE-2019-15845
Path matching might pass in File.fnmatch and File.fnmatch? due
to a NUL character injection.

CVE-2019-16201
A loop caused by a wrong regular expression could lead to a denial
of service of a WEBrick service.

CVE-2019-16254
This is the same issue as CVE-2017-17742, whose fix was not complete.

CVE-2019-16255
Giving untrusted data to the first argument of Shell#[] and
Shell#test might lead to a code injection vulnerability." );
	script_tag( name: "affected", value: "'ruby2.1' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2.1.5-2+deb8u8.

We recommend that you upgrade your ruby2.1 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libruby2.1", ver: "2.1.5-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby2.1", ver: "2.1.5-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby2.1-dev", ver: "2.1.5-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby2.1-doc", ver: "2.1.5-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby2.1-tcltk", ver: "2.1.5-2+deb8u8", rls: "DEB8" ) )){
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

