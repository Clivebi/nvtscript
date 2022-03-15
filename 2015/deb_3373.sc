if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703373" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2015-4716", "CVE-2015-4717", "CVE-2015-4718", "CVE-2015-5953", "CVE-2015-5954", "CVE-2015-6500", "CVE-2015-6670", "CVE-2015-7699" );
	script_name( "Debian Security Advisory DSA 3373-1 (owncloud - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-10-18 00:00:00 +0200 (Sun, 18 Oct 2015)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3373.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "owncloud on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 7.0.4+dfsg-4~deb8u3.

For the testing distribution (stretch), these problems have been fixed
in version 7.0.10~dfsg-2 or earlier versions.

For the unstable distribution (sid), these problems have been fixed in
version 7.0.10~dfsg-2 or earlier versions.

We recommend that you upgrade your owncloud packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities were discovered
in ownCloud, a cloud storage web service for files, music, contacts, calendars and
many more. These flaws may lead to the execution of arbitrary code, authorization
bypass, information disclosure, cross-site scripting or denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "owncloud", ver: "7.0.4+dfsg-4~deb8u3", rls: "DEB8" ) ) != NULL){
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

