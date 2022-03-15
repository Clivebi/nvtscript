if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71152" );
	script_version( "2021-08-27T12:01:24+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 12:01:24 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-03-12 11:33:12 -0400 (Mon, 12 Mar 2012)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-13 15:21:00 +0000 (Tue, 13 Jul 2021)" );
	script_name( "Debian Security Advisory DSA 2424-1 (libxml-atom-perl)" );
	script_cve_id( "CVE-2012-1102" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202424-1" );
	script_tag( name: "insight", value: "It was discovered that the XML::Atom Perl module did not disable
external entities when parsing XML from potentially untrusted sources.
This may allow attackers to gain read access to otherwise protected
resources, depending on how the library is used.

For the stable distribution (squeeze), this problem has been fixed in
version 0.37-1+squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 0.39-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your libxml-atom-perl packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to libxml-atom-perl
announced via advisory DSA 2424-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxml-atom-perl", ver: "0.37-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml-atom-perl", ver: "0.41-1", rls: "DEB7" ) ) != NULL){
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

