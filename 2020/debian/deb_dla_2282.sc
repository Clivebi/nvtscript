if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892282" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2020-8163", "CVE-2020-8164", "CVE-2020-8165" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-17 12:15:00 +0000 (Sat, 17 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-07-21 03:01:31 +0000 (Tue, 21 Jul 2020)" );
	script_name( "Debian LTS: Security Advisory for rails (DLA-2282-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/07/msg00013.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2282-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rails'
  package(s) announced via the DLA-2282-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities were found in Ruby on Rails, a MVC ruby-based
framework geared for web application development, which could lead to
remote code execution and untrusted user input usage, depending on the
application.

CVE-2020-8163

A code injection vulnerability in Rails would allow an attacker
who controlled the `locals` argument of a `render` call to perform
a RCE.

CVE-2020-8164

A deserialization of untrusted data vulnerability exists in rails
which can allow an attacker to supply information can be
inadvertently leaked from Strong Parameters.

CVE-2020-8165

A deserialization of untrusted data vulnernerability exists in
rails that can allow an attacker to unmarshal user-provided objects
in MemCacheStore and RedisCacheStore potentially resulting in an
RCE." );
	script_tag( name: "affected", value: "'rails' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
2:4.2.7.1-1+deb9u3.

We recommend that you upgrade your rails packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "rails", ver: "2:4.2.7.1-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-actionmailer", ver: "2:4.2.7.1-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-actionpack", ver: "2:4.2.7.1-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-actionview", ver: "2:4.2.7.1-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-activejob", ver: "2:4.2.7.1-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-activemodel", ver: "2:4.2.7.1-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-activerecord", ver: "2:4.2.7.1-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-activesupport", ver: "2:4.2.7.1-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-rails", ver: "2:4.2.7.1-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-railties", ver: "2:4.2.7.1-1+deb9u3", rls: "DEB9" ) )){
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

