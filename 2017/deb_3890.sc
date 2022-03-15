if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703890" );
	script_version( "2021-09-16T13:01:47+0000" );
	script_cve_id( "CVE-2017-9736" );
	script_name( "Debian Security Advisory DSA 3890-1 (spip - security update)" );
	script_tag( name: "last_modification", value: "2021-09-16 13:01:47 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-21 00:00:00 +0200 (Wed, 21 Jun 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3890.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(10|9)" );
	script_tag( name: "affected", value: "spip on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 3.1.4-3~deb9u1.

For the testing distribution (buster), this problem has been fixed
in version 3.1.4-3.

For the unstable distribution (sid), this problem has been fixed in
version 3.1.4-3.

We recommend that you upgrade your spip packages." );
	script_tag( name: "summary", value: "Emeric Boit of ANSSI reported that SPIP, a website engine for
publishing, insufficiently sanitises the value from the X-Forwarded-Host
HTTP header field. An unauthenticated attacker can take advantage of
this flaw to cause remote code execution." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "spip", ver: "3.1.4-3", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "spip", ver: "3.1.4-3~deb9u1", rls: "DEB9" ) ) != NULL){
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

