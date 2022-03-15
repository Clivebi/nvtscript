if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702456" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-0920" );
	script_name( "Debian Security Advisory DSA 2456-1 (dropbear - use after free)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2012/dsa-2456.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "dropbear on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 0.52-5+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 2012.55-1.

For the unstable distribution (sid), this problem has been fixed in
version 2012.55-1.

We recommend that you upgrade your dropbear packages." );
	script_tag( name: "summary", value: "Danny Fullerton discovered a use-after-free in the Dropbear SSH daemon,
resulting in potential execution of arbitrary code. Exploitation is
limited to users, who have been authenticated through public key
authentication and for which command restrictions are in place." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "dropbear", ver: "0.52-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dropbear", ver: "2012.55-1", rls: "DEB7" ) ) != NULL){
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

