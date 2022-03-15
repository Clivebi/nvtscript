if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703177" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-2091" );
	script_name( "Debian Security Advisory DSA 3177-1 (mod-gnutls - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-03-10 00:00:00 +0100 (Tue, 10 Mar 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3177.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "mod-gnutls on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 0.5.10-1.1+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 0.6-1.3.

We recommend that you upgrade your mod-gnutls packages." );
	script_tag( name: "summary", value: "Thomas Klute discovered that in
mod-gnutls, an Apache module providing SSL and TLS encryption with GnuTLS,
a bug caused the server's client verify mode not to be considered at all,
in case the directory's configuration was unset. Clients with invalid
certificates were then able to leverage this flaw in order to get access to
that directory." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libapache2-mod-gnutls", ver: "0.5.10-1.1+deb7u1", rls: "DEB7" ) ) != NULL){
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
