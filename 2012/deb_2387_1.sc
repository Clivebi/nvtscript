if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70705" );
	script_cve_id( "CVE-2012-0040" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 03:27:28 -0500 (Sat, 11 Feb 2012)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Debian Security Advisory DSA 2387-1 (simplesamlphp)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202387-1" );
	script_tag( name: "insight", value: "timtai1 discovered that simpleSAMLphp, an authentication and federation
platform, is vulnerable to a cross site scripting attack, allowing a
remote attacker to access sensitive client data.

The oldstable distribution (lenny) does not contain a simplesamlphp
package.

For the stable distribution (squeeze), this problem has been fixed in
version 1.6.3-3.

For the unstable distribution (sid), this problem has been fixed in
version 1.8.2-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your simplesamlphp packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to simplesamlphp
announced via advisory DSA 2387-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "simplesamlphp", ver: "1.6.3-3", rls: "DEB6" ) ) != NULL){
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

