if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704109" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_cve_id( "CVE-2017-18076" );
	script_name( "Debian Security Advisory DSA 4109-1 (ruby-omniauth - security update)" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-09 00:00:00 +0100 (Fri, 09 Feb 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4109.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "ruby-omniauth on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 1.2.1-1+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 1.3.1-1+deb9u1.

We recommend that you upgrade your ruby-omniauth packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/ruby-omniauth" );
	script_tag( name: "summary", value: "Lalith Rallabhandi discovered that OmniAuth, a Ruby library for
implementing multi-provider authentication in web applications,
mishandled and leaked sensitive information. An attacker with access to
the callback environment, such as in the case of a crafted web
application, can request authentication services from this module and
access to the CSRF token." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ruby-omniauth", ver: "1.2.1-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-omniauth", ver: "1.3.1-1+deb9u1", rls: "DEB9" ) )){
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
