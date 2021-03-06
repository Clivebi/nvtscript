if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702875" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2013-6474", "CVE-2013-6475", "CVE-2013-6476" );
	script_name( "Debian Security Advisory DSA 2875-1 (cups-filters - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-03-12 00:00:00 +0100 (Wed, 12 Mar 2014)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2875.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "cups-filters on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 1.0.18-2.1+deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 1.0.47-1.

We recommend that you upgrade your cups-filters packages." );
	script_tag( name: "summary", value: "Florian Weimer of the Red Hat Product Security Team discovered multiple
vulnerabilities in the pdftoopvp CUPS filter, which could result in the
execution of aribitrary code if a malformed PDF file is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "cups-filters", ver: "1.0.18-2.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsfilters-dev", ver: "1.0.18-2.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsfilters1", ver: "1.0.18-2.1+deb7u1", rls: "DEB7" ) ) != NULL){
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

