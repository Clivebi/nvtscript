if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703239" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-3026" );
	script_name( "Debian Security Advisory DSA 3239-1 (icecast2 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-04-29 00:00:00 +0200 (Wed, 29 Apr 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3239.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "icecast2 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 2.4.0-1.1+deb8u1.

For the testing distribution (stretch), this problem will be fixed in
version 2.4.2-1.

For the unstable distribution (sid), this problem has been fixed in
version 2.4.2-1.

We recommend that you upgrade your icecast2 packages." );
	script_tag( name: "summary", value: "Juliane Holzt discovered that Icecast2, a streaming media server, could
dereference a NULL pointer when URL authentication is configured and the
stream_auth URL is triggered by a client without setting any credentials.
This could allow remote attackers to cause a denial of service (crash)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "icecast2", ver: "2.4.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icecast2", ver: "2.4.0-1.1+deb8u1", rls: "DEB8" ) ) != NULL){
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

