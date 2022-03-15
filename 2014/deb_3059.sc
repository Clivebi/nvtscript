if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703059" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-8761", "CVE-2014-8762", "CVE-2014-8763", "CVE-2014-8764" );
	script_name( "Debian Security Advisory DSA 3059-1 (dokuwiki - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-10-29 00:00:00 +0100 (Wed, 29 Oct 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3059.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "dokuwiki on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 0.0.20120125b-2+deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 0.0.20140929.a-1.

We recommend that you upgrade your dokuwiki packages." );
	script_tag( name: "summary", value: "Two vulnerabilities have been discovered in dokuwiki. Access control in
the media manager was insufficiently restricted and authentication could
be bypassed when using Active Directory for LDAP authentication." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "dokuwiki", ver: "0.0.20120125b-2+deb7u1", rls: "DEB7" ) ) != NULL){
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

