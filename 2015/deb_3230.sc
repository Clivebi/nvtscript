if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703230" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-0846" );
	script_name( "Debian Security Advisory DSA 3230-1 (django-markupfield - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-04-20 00:00:00 +0200 (Mon, 20 Apr 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3230.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "django-markupfield on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 1.0.2-2+deb7u1.

For the upcoming stable distribution (jessie), this problem has been
fixed in version 1.2.1-2+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 1.3.2-1.

We recommend that you upgrade your django-markupfield packages." );
	script_tag( name: "summary", value: "James P. Turk discovered that the ReST
renderer in django-markupfield, a custom Django field for easy use of markup in
text fields, didn't disable the ..raw directive, allowing remote attackers to
include arbitrary files." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-django-markupfield", ver: "1.0.2-2+deb7u1", rls: "DEB7" ) ) != NULL){
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

