if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71258" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-2093", "CVE-2012-2086", "CVE-2012-2085" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:57:45 -0400 (Mon, 30 Apr 2012)" );
	script_name( "Debian Security Advisory DSA 2453-2 (gajim)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202453-2" );
	script_tag( name: "insight", value: "It was discovered that the last security update for gajim, DSA-2453-1,
introduced a regression in certain environments.

For the stable distribution (squeeze), this problem has been fixed in
version 0.13.4-3+squeeze3." );
	script_tag( name: "solution", value: "We recommend that you upgrade your gajim packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to gajim
announced via advisory DSA 2453-2." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gajim", ver: "0.13.4-3+squeeze3", rls: "DEB6" ) ) != NULL){
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

