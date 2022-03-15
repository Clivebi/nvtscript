if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703807" );
	script_version( "2021-09-17T10:01:50+0000" );
	script_cve_id( "CVE-2017-6009", "CVE-2017-6010", "CVE-2017-6011" );
	script_name( "Debian Security Advisory DSA 3807-1 (icoutils - security update)" );
	script_tag( name: "last_modification", value: "2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-12 00:00:00 +0100 (Sun, 12 Mar 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-12 19:52:00 +0000 (Tue, 12 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3807.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "icoutils on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 0.31.0-2+deb8u3.

For the upcoming stable distribution (stretch), these problems have been
fixed in version 0.31.2-1.

For the unstable distribution (sid), these problems have been fixed in
version 0.31.2-1.

We recommend that you upgrade your icoutils packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities were discovered in the icotool and wrestool
tools of Icoutils, a set of programs that deal with MS Windows icons and
cursors, which may result in denial of service or the execution of
arbitrary code if a malformed .ico or .exe file is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "icoutils", ver: "0.31.0-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icoutils", ver: "0.31.2-1", rls: "DEB9" ) ) != NULL){
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

