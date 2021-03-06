if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704481" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2019-13574" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-07-14 02:00:05 +0000 (Sun, 14 Jul 2019)" );
	script_name( "Debian Security Advisory DSA 4481-1 (ruby-mini-magick - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(10|9)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4481.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4481-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby-mini-magick'
  package(s) announced via the DSA-4481-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Harsh Jaiswal discovered a remote shell execution vulnerability in
ruby-mini-magick, a Ruby library providing a wrapper around ImageMagick
or GraphicsMagick, exploitable when using MiniMagick::Image.open with
specially crafted URLs coming from unsanitized user input." );
	script_tag( name: "affected", value: "'ruby-mini-magick' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), this problem has been fixed
in version 4.5.1-1+deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 4.9.2-1+deb10u1.

We recommend that you upgrade your ruby-mini-magick packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ruby-mini-magick", ver: "4.9.2-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-mini-magick", ver: "4.5.1-1+deb9u1", rls: "DEB9" ) )){
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

