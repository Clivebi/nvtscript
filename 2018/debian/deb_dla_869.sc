if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890869" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_cve_id( "CVE-2017-5613", "CVE-2017-5614", "CVE-2017-5615", "CVE-2017-5616" );
	script_name( "Debian LTS: Security Advisory for cgiemail (DLA-869-1)" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-12 00:00:00 +0100 (Fri, 12 Jan 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-03-07 13:38:00 +0000 (Tue, 07 Mar 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/03/msg00026.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "cgiemail on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.6-37+deb7u1.

We recommend that you upgrade your cgiemail packages." );
	script_tag( name: "summary", value: "The cPanel Security Team discovered several security vulnerabilities in
cgiemail, a CGI program used to create HTML forms for sending mails:

CVE-2017-5613

A format string injection vulnerability allowed to supply arbitrary
format strings to cgiemail and cgiecho. A local attacker with
permissions to provide a cgiemail template could use this
vulnerability to execute code as webserver user.
Format strings in cgiemail templates are now restricted to simple
%s, %U and %H sequences.

CVE-2017-5614

An open redirect vulnerability in cgiemail and cgiecho binaries
could be exploited by a local attacker to force redirect to an
arbitrary URL. These redirects are now limited to the domain that
handled the request.

CVE-2017-5615

A vulnerability in cgiemail and cgiecho binaries allowed injection
of additional HTTP headers. Newline characters are now stripped
from the redirect location to protect against this.

CVE-2017-5616

Missing escaping of the addendum parameter lead to a reflected
cross-site (XSS) vulnerability in cgiemail and cgiecho binaries.
The output is now html escaped." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "cgiemail", ver: "1.6-37+deb7u1", rls: "DEB7" ) )){
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

