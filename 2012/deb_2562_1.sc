if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72535" );
	script_cve_id( "CVE-2012-4510" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-10-29 10:19:57 -0400 (Mon, 29 Oct 2012)" );
	script_name( "Debian Security Advisory DSA 2562-1 (cups-pk-helper)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202562-1" );
	script_tag( name: "insight", value: "cups-pk-helper, a PolicyKit helper to configure cups with fine-grained
privileges, wraps CUPS function calls in an insecure way. This could
lead to uploading sensitive data to a cups resource, or overwriting
specific files with the content of a cups resource. The user would have
to explicitly approve the action.

For the stable distribution (squeeze), this problem has been fixed in
version 0.1.0-3.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 0.2.3-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your cups-pk-helper packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to cups-pk-helper
announced via advisory DSA 2562-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "cups-pk-helper", ver: "0.1.0-3", rls: "DEB6" ) ) != NULL){
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

