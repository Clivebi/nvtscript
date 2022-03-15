if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892655" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2021-22885", "CVE-2021-22904" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-10 16:15:00 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-05-12 03:00:13 +0000 (Wed, 12 May 2021)" );
	script_name( "Debian LTS: Security Advisory for rails (DLA-2655-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/05/msg00010.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2655-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2655-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/988214" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rails'
  package(s) announced via the DLA-2655-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "CVE-2021-22885

There is a possible information disclosure/unintended method
execution vulnerability in Action Pack when using the
`redirect_to` or `polymorphic_url` helper with untrusted user
input.

CVE-2021-22904

There is a possible DoS vulnerability in the Token Authentication
logic in Action Controller. Impacted code uses
`authenticate_or_request_with_http_token` or
`authenticate_with_http_token` for request authentication." );
	script_tag( name: "affected", value: "'rails' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
2:4.2.7.1-1+deb9u5.

We recommend that you upgrade your rails packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "rails", ver: "2:4.2.7.1-1+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-actionmailer", ver: "2:4.2.7.1-1+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-actionpack", ver: "2:4.2.7.1-1+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-actionview", ver: "2:4.2.7.1-1+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-activejob", ver: "2:4.2.7.1-1+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-activemodel", ver: "2:4.2.7.1-1+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-activerecord", ver: "2:4.2.7.1-1+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-activesupport", ver: "2:4.2.7.1-1+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-rails", ver: "2:4.2.7.1-1+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-railties", ver: "2:4.2.7.1-1+deb9u5", rls: "DEB9" ) )){
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

