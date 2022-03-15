if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702428" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-1136", "CVE-2012-1142", "CVE-2012-1133", "CVE-2012-1144", "CVE-2012-1134" );
	script_name( "Debian Security Advisory DSA 2428-1 (freetype - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2012/dsa-2428.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "freetype on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
  version 2.4.2-2.1+squeeze4. The updated packages are already available
  since yesterday, but the advisory text couldn't be send earlier.

  For the unstable distribution (sid), this problem will be fixed soon.

  We recommend that you upgrade your freetype packages." );
	script_tag( name: "summary", value: "Mateusz Jurczyk from the Google Security Team discovered several
  vulnerabilities in Freetype's parsing of BDF, Type1 and TrueType fonts, which could result in the
  execution of arbitrary code if a malformed font file is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "freetype2-demos", ver: "2.4.2-2.1+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreetype6", ver: "2.4.2-2.1+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreetype6-dev", ver: "2.4.2-2.1+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreetype6-udeb", ver: "2.4.2-2.1+squeeze4", rls: "DEB6" ) ) != NULL){
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

