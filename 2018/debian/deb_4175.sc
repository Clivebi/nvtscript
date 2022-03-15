if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704175" );
	script_version( "2021-06-18T11:51:03+0000" );
	script_cve_id( "CVE-2018-1000069" );
	script_name( "Debian Security Advisory DSA 4175-1 (freeplane - security update)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:51:03 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-18 00:00:00 +0200 (Wed, 18 Apr 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-14 17:31:00 +0000 (Thu, 14 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4175.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB[89]" );
	script_tag( name: "affected", value: "freeplane on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 1.3.12-1+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 1.5.18-1+deb9u1.

We recommend that you upgrade your freeplane packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/freeplane" );
	script_tag( name: "summary", value: "Wojciech Regula discovered an XML External Entity vulnerability in the
XML Parser of the mindmap loader in freeplane, a Java program for
working with mind maps, resulting in potential information disclosure if
a malicious mind map file is opened." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "freeplane", ver: "1.3.12-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjortho-freeplane-java", ver: "1.3.12-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "freeplane", ver: "1.5.18-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "freeplane-scripting-api", ver: "1.5.18-1+deb9u1", rls: "DEB9" ) )){
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

