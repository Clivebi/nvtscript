if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891303" );
	script_version( "2021-06-17T11:00:26+0000" );
	script_cve_id( "CVE-2018-7536", "CVE-2018-7537" );
	script_name( "Debian LTS: Security Advisory for python-django (DLA-1303-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:00:26 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-27 00:00:00 +0200 (Tue, 27 Mar 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-28 21:21:00 +0000 (Thu, 28 Feb 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/03/msg00006.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "python-django on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.4.22-1+deb7u4.

We recommend that you upgrade your python-django packages." );
	script_tag( name: "summary", value: "Several functions were extremely slow to evaluate certain inputs due to
catastrophic backtracking vulnerabilities in several regular expressions.

CVE-2018-7536

The django.utils.html.urlize() function was extremely slow to evaluate
certain inputs due to catastrophic backtracking vulnerabilities in two
regular expressions. The urlize() function is used to implement the urlize
and urlizetrunc template filters, which were thus vulnerable.

The problematic regular expressions are replaced with parsing logic that
behaves similarly.

CVE-2018-7537

If django.utils.text.Truncator's chars() and words() methods were passed
the html=True argument, they were extremely slow to evaluate certain inputs
due to a catastrophic backtracking vulnerability in a regular expression.
The chars() and words() methods are used to implement the truncatechars_html
and truncatewords_html template filters, which were thus vulnerable.

The backtracking problem in the regular expression is fixed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-django", ver: "1.4.22-1+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-django-doc", ver: "1.4.22-1+deb7u4", rls: "DEB7" ) )){
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

