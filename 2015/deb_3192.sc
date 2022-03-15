if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703192" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-0885" );
	script_name( "Debian Security Advisory DSA 3192-1 (checkpw - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-03-17 00:00:00 +0100 (Tue, 17 Mar 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3192.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "checkpw on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 1.02-1+deb7u1.

For the upcoming stable distribution (jessie), this problem has been
fixed in version 1.02-1.1.

For the unstable distribution (sid), this problem has been fixed in
version 1.02-1.1.

We recommend that you upgrade your checkpw packages." );
	script_tag( name: "summary", value: "Hiroya Ito of GMO Pepabo, Inc. reported
that checkpw, a password authentication program, has a flaw in processing account
names which contain double dashes. A remote attacker can use this flaw to cause a
denial of service (infinite loop)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "checkpw", ver: "1.02-1+deb7u1", rls: "DEB7" ) ) != NULL){
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

