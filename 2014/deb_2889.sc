if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702889" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-2655" );
	script_name( "Debian Security Advisory DSA 2889-1 (postfixadmin - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-03-28 00:00:00 +0100 (Fri, 28 Mar 2014)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2889.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "postfixadmin on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 2.3.5-2+deb7u1.

For the testing distribution (jessie), and unstable distribution
(sid), this problem has been fixed in version 2.3.5-3.

We recommend that you upgrade your postfixadmin packages." );
	script_tag( name: "summary", value: "An SQL injection vulnerability was discovered in postfixadmin, a web
administration interface for the Postfix Mail Transport Agent, which
allowed authenticated users to make arbitrary manipulations to the
database.

The oldstable distribution (squeeze) does not contain postfixadmin." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "postfixadmin", ver: "2.3.5-2+deb7u1", rls: "DEB7" ) ) != NULL){
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

