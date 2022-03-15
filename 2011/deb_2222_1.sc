if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69565" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2011-1499" );
	script_name( "Debian Security Advisory DSA 2222-1 (tinyproxy)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202222-1" );
	script_tag( name: "insight", value: "Christoph Martin discovered that incorrect ACL processing in TinyProxy,
a lightweight, non-caching, optionally anonymizing http proxy could
lead to unintended network access rights.

The oldstable distribution (lenny) is not affected.

For the stable distribution (squeeze), this problem has been fixed in
version 1.8.2-1squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 1.8.2-2" );
	script_tag( name: "solution", value: "We recommend that you upgrade your tinyproxy packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to tinyproxy
announced via advisory DSA 2222-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "tinyproxy", ver: "1.8.2-1squeeze1", rls: "DEB6" ) ) != NULL){
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

