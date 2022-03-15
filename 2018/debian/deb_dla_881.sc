if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890881" );
	script_version( "2020-01-29T08:22:52+0000" );
	script_cve_id( "CVE-2014-8760" );
	script_name( "Debian LTS: Security Advisory for ejabberd (DLA-881-1)" );
	script_tag( name: "last_modification", value: "2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)" );
	script_tag( name: "creation_date", value: "2018-01-17 00:00:00 +0100 (Wed, 17 Jan 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/04/msg00000.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "ejabberd on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', this problem has been fixed in version
2.1.10-4+deb7u2.

This update also disables the insecure SSLv3.

We recommend that you upgrade your ejabberd packages." );
	script_tag( name: "summary", value: "It was found that ejabberd does not enforce the starttls_required
setting when compression is used, which causes clients to establish
connections without encryption." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ejabberd", ver: "2.1.10-4+deb7u2", rls: "DEB7" ) )){
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

