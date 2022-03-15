if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892192" );
	script_version( "2020-05-01T03:00:18+0000" );
	script_cve_id( "CVE-2013-0269", "CVE-2020-10663" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-05-01 03:00:18 +0000 (Fri, 01 May 2020)" );
	script_tag( name: "creation_date", value: "2020-05-01 03:00:18 +0000 (Fri, 01 May 2020)" );
	script_name( "Debian LTS: Security Advisory for ruby2.1 (DLA-2192-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/04/msg00030.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2192-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby2.1'
  package(s) announced via the DLA-2192-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The JSON gem through 2.2.0 for Ruby, as used in Ruby 2.1 has an
unsafe object creation vulnerability.
This is quite similar to CVE-2013-0269, but does not rely on poor
garbage-collection behavior within Ruby. Specifically, use of JSON
parsing methods can lead to creation of a malicious object within
the interpreter, with adverse effects that are application-dependent." );
	script_tag( name: "affected", value: "'ruby2.1' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.1.5-2+deb8u10.

We recommend that you upgrade your ruby2.1 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libruby2.1", ver: "2.1.5-2+deb8u10", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby2.1", ver: "2.1.5-2+deb8u10", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby2.1-dev", ver: "2.1.5-2+deb8u10", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby2.1-doc", ver: "2.1.5-2+deb8u10", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby2.1-tcltk", ver: "2.1.5-2+deb8u10", rls: "DEB8" ) )){
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

