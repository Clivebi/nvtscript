if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703321" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-0851" );
	script_name( "Debian Security Advisory DSA 3321-1 (xmltooling - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-07-30 00:00:00 +0200 (Thu, 30 Jul 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3321.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "xmltooling on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), this problem has been fixed
in version 1.4.2-5+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 1.5.3-2+deb8u1.

For the unstable distribution (sid), this problem will be fixed shortly.

We recommend that you upgrade your xmltooling packages." );
	script_tag( name: "summary", value: "The InCommon Shibboleth Training team discovered that XMLTooling, a
C++ XML parsing library, did not properly handle an exception when
parsing well-formed but schema-invalid XML. This could allow remote
attackers to cause a denial of service (crash) via crafted XML data." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxmltooling-dev", ver: "1.4.2-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxmltooling-doc", ver: "1.4.2-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxmltooling5", ver: "1.4.2-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xmltooling-schemas", ver: "1.4.2-5+deb7u1", rls: "DEB7" ) ) != NULL){
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

