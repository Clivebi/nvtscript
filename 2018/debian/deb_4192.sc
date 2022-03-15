if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704192" );
	script_version( "2021-06-21T03:34:17+0000" );
	script_cve_id( "CVE-2017-8372", "CVE-2017-8373", "CVE-2017-8374" );
	script_name( "Debian Security Advisory DSA 4192-1 (libmad - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 03:34:17 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-04 00:00:00 +0200 (Fri, 04 May 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-20 01:29:00 +0000 (Sun, 20 May 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4192.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB[89]" );
	script_tag( name: "affected", value: "libmad on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 0.15.1b-8+deb8u1.

For the stable distribution (stretch), these problems have been fixed in
version 0.15.1b-8+deb9u1.

We recommend that you upgrade your libmad packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/libmad" );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in MAD, an MPEG audio decoder
library, which could result in denial of service if a malformed audio
file is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmad0", ver: "0.15.1b-8+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmad0-dev", ver: "0.15.1b-8+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmad0", ver: "0.15.1b-8+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmad0-dev", ver: "0.15.1b-8+deb8u1", rls: "DEB8" ) )){
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

