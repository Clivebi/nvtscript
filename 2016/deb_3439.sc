if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703439" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-1231", "CVE-2016-1232" );
	script_name( "Debian Security Advisory DSA 3439-1 (prosody - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-01-10 00:00:00 +0100 (Sun, 10 Jan 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3439.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|7)" );
	script_tag( name: "affected", value: "prosody on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution
(wheezy), these problems have been fixed in version 0.8.2-4+deb7u3.

For the stable distribution (jessie), these problems have been fixed in
version 0.9.7-2+deb8u2.

We recommend that you upgrade your prosody packages." );
	script_tag( name: "summary", value: "Two vulnerabilities were discovered
in Prosody, a lightweight Jabber/XMPP server. The Common Vulnerabilities and
Exposures project identifies the following issues:

CVE-2016-1231
Kim Alvefur discovered a flaw in Prosody's HTTP file-serving module
that allows it to serve requests outside of the configured public
root directory. A remote attacker can exploit this flaw to access
private files including sensitive data. The default configuration
does not enable the mod_http_files module and thus is not
vulnerable.

CVE-2016-1232
Thijs Alkemade discovered that Prosody's generation of the secret
token for server-to-server dialback authentication relied upon a
weak random number generator that was not cryptographically secure.
A remote attacker can take advantage of this flaw to guess at
probable values of the secret key and impersonate the affected
domain to other servers on the network." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "prosody", ver: "0.9.7-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "prosody", ver: "0.8.2-4+deb7u3", rls: "DEB7" ) ) != NULL){
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

