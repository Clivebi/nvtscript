if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702659" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-1915" );
	script_name( "Debian Security Advisory DSA 2659-1 (libapache-mod-security - XML external entity processing vulnerability)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-04-09 00:00:00 +0200 (Tue, 09 Apr 2013)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2659.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "libapache-mod-security on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 2.5.12-1+squeeze2.

For the testing distribution (wheezy), this problem has been fixed in
version 2.6.6-6 of the modsecurity-apache package.

For the unstable distribution (sid), this problem has been fixed in
version 2.6.6-6 of the modsecurity-apache package.

We recommend that you upgrade your libapache-mod-security packages." );
	script_tag( name: "summary", value: "Timur Yunusov and Alexey Osipov from Positive Technologies discovered
that the XML files parser of ModSecurity, an Apache module whose purpose
is to tighten the Web application security, is vulnerable to XML
external entities attacks. A specially-crafted XML file provided by a
remote attacker, could lead to local file disclosure or excessive
resources (CPU, memory) consumption when processed.

This update introduces a SecXmlExternalEntity option which is Off

by default. This will disable the ability of libxml2 to load external
entities." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libapache-mod-security", ver: "2.5.12-1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mod-security-common", ver: "2.5.12-1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapache-mod-security", ver: "2.6.6-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapache2-modsecurity", ver: "2.6.6-6", rls: "DEB7" ) ) != NULL){
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

