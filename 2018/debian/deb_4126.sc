if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704126" );
	script_version( "2021-06-18T11:51:03+0000" );
	script_cve_id( "CVE-2018-0489" );
	script_name( "Debian Security Advisory DSA 4126-1 (xmltooling - security update)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:51:03 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-27 00:00:00 +0100 (Tue, 27 Feb 2018)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-23 15:18:00 +0000 (Fri, 23 Mar 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4126.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "xmltooling on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 1.5.3-2+deb8u3.

For the stable distribution (stretch), this problem has been fixed in
version 1.6.0-4+deb9u1.

We recommend that you upgrade your xmltooling packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/xmltooling" );
	script_tag( name: "summary", value: "Kelby Ludwig and Scott Cantor discovered that the Shibboleth service
provider is vulnerable to impersonation attacks and information
disclosure due to incorrect XML parsing." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxmltooling-dev", ver: "1.6.0-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxmltooling-doc", ver: "1.6.0-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxmltooling7", ver: "1.6.0-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xmltooling-schemas", ver: "1.6.0-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxmltooling-dev", ver: "1.5.3-2+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxmltooling-doc", ver: "1.5.3-2+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxmltooling6", ver: "1.5.3-2+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xmltooling-schemas", ver: "1.5.3-2+deb8u3", rls: "DEB8" ) )){
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

