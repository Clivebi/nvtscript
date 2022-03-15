if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703715" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-7146", "CVE-2016-7148", "CVE-2016-9119" );
	script_name( "Debian Security Advisory DSA 3715-1 (moin - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-11-15 00:00:00 +0100 (Tue, 15 Nov 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3715.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "moin on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 1.9.8-1+deb8u1.

We recommend that you upgrade your moin packages." );
	script_tag( name: "summary", value: "Several cross-site scripting vulnerabilities were discovered in moin, a
Python clone of WikiWiki. A remote attacker can conduct cross-site
scripting attacks via the GUI editor's attachment dialogue
(CVE-2016-7146),
the AttachFile view (CVE-2016-7148)
and the GUI editor's link dialogue (CVE-2016-9119
)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-moinmoin", ver: "1.9.8-1+deb8u1", rls: "DEB8" ) ) != NULL){
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

