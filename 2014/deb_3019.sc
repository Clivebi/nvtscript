if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703019" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-3618" );
	script_name( "Debian Security Advisory DSA 3019-1 (procmail - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-09-04 00:00:00 +0200 (Thu, 04 Sep 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3019.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "procmail on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 3.22-20+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 3.22-22.

We recommend that you upgrade your procmail packages." );
	script_tag( name: "summary", value: "Boris pi
Piwinger and Tavis Ormandy reported a heap overflow
vulnerability in procmail's formail utility when processing
specially-crafted email headers. A remote attacker could use this flaw
to cause formail to crash, resulting in a denial of service or data
loss, or possibly execute arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "procmail", ver: "3.22-20+deb7u1", rls: "DEB7" ) ) != NULL){
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

