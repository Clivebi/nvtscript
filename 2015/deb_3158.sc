if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703158" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2014-9274", "CVE-2014-9275" );
	script_name( "Debian Security Advisory DSA 3158-1 (unrtf - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-02-09 00:00:00 +0100 (Mon, 09 Feb 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3158.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "unrtf on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problems have been fixed in version 0.21.5-3~deb7u1. This update is based
on a new upstream version of unrtf including additional bug fixes, new features
and incompatible changes (especially PostScript support is dropped).

For the upcoming stable distribution (jessie) and the unstable
distribution (sid), these problems have been fixed in version 0.21.5-2.

We recommend that you upgrade your unrtf packages." );
	script_tag( name: "summary", value: "Michal Zalewski and Hanno Boeck
discovered several vulnerabilities in unrtf, a RTF to other formats converter,
leading to a denial of service (application crash) or, potentially, the execution
of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "unrtf", ver: "0.21.5-3~deb7u1", rls: "DEB7" ) ) != NULL){
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

